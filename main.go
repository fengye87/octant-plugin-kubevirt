package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/vmware-tanzu/octant/pkg/action"
	"github.com/vmware-tanzu/octant/pkg/navigation"
	"github.com/vmware-tanzu/octant/pkg/plugin"
	"github.com/vmware-tanzu/octant/pkg/plugin/service"
	"github.com/vmware-tanzu/octant/pkg/store"
	"github.com/vmware-tanzu/octant/pkg/view/component"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	kubevirtv1 "kubevirt.io/api/core/v1"
)

const (
	actionVMOpenConsole = "action.kubevirt.io/virtualmachines/openconsole"
	actionVMStart       = "action.kubevirt.io/virtualmachines/start"
	actionVMStop        = "action.kubevirt.io/virtualmachines/stop"
	actionVMPause       = "action.kubevirt.io/virtualmachines/pause"
	actionVMUnpause     = "action.kubevirt.io/virtualmachines/unpause"
	actionVMRestart     = "action.kubevirt.io/virtualmachines/restart"
	actionVMSoftReboot  = "action.kubevirt.io/virtualmachines/softreboot"
)

var (
	logger = service.NewLoggerHelper()
	scheme = runtime.NewScheme()

	kubevirtGroup            = "kubevirt.io"
	kubevirtSubresourceGroup = "subresources." + kubevirtGroup
	kubevirtVersion          = "v1"
	vmGVK                    = schema.GroupVersionKind{
		Group:   kubevirtGroup,
		Version: kubevirtVersion,
		Kind:    "VirtualMachine",
	}
	vmiGVK = schema.GroupVersionKind{
		Group:   kubevirtGroup,
		Version: kubevirtVersion,
		Kind:    "VirtualMachineInstance",
	}
)

func init() {
	kubevirtv1.AddToScheme(scheme)
}

func main() {
	// Remove the prefix from the go logger since Octant will print logs with timestamps.
	log.SetPrefix("")

	// Tell Octant to call this plugin when printing configuration or tabs for VMs
	capabilities := &plugin.Capabilities{
		SupportsPrinterConfig: []schema.GroupVersionKind{vmGVK},
		SupportsObjectStatus:  []schema.GroupVersionKind{vmGVK},
		SupportsTab:           []schema.GroupVersionKind{vmGVK},
		ActionNames:           []string{actionVMOpenConsole, actionVMStart, actionVMStop, actionVMPause, actionVMUnpause, actionVMRestart, actionVMSoftReboot},
		IsModule:              true,
	}

	// Set up what should happen when Octant calls this plugin.
	options := []service.PluginOption{
		service.WithPrinter(handlePrint),
		// service.WithTabPrinter(handleTab),
		service.WithNavigation(handleNavigation, initRoutes),
		service.WithActionHandler(handleAction),
	}

	// Use the plugin service helper to register this plugin.
	p, err := service.Register("virtualization-overview", "Virtualization module is used to display all virtualization related resources", capabilities, options...)
	if err != nil {
		log.Fatal(err)
	}

	logger.Info("octant-plugin-kubevirt is starting")
	service.SetupPluginLogger(service.Info)
	p.Serve()
}

// handlePrint is called when Octant wants to print an object.
func handlePrint(request *service.PrintRequest) (plugin.PrintResponse, error) {
	vmKey, err := store.KeyFromObject(request.Object)
	if err != nil {
		return plugin.PrintResponse{}, fmt.Errorf("get VM key from request: %s", err)
	}

	unstructured, err := request.DashboardClient.Get(request.Context(), vmKey)
	if err != nil {
		return plugin.PrintResponse{}, fmt.Errorf("get VM: %s", err)
	}

	var vm kubevirtv1.VirtualMachine
	if err := scheme.Convert(unstructured, &vm, request.Context()); err != nil {
		return plugin.PrintResponse{}, fmt.Errorf("convert VM: %s", err)
	}

	var vmConfigSections []component.SummarySection
	if vm.Spec.Template.Spec.Domain.CPU != nil {
		vmConfigSections = append(vmConfigSections, component.SummarySection{
			Header: "CPU",
			Content: component.NewText(fmt.Sprintf("%d (%d cores per socket, %d sockets)", vm.Spec.Template.Spec.Domain.CPU.Sockets*vm.Spec.Template.Spec.Domain.CPU.Cores,
				vm.Spec.Template.Spec.Domain.CPU.Sockets, vm.Spec.Template.Spec.Domain.CPU.Cores)),
		})
	}
	if vm.Spec.Template.Spec.Domain.Memory != nil {
		if vm.Spec.Template.Spec.Domain.Memory.Guest != nil {
			vmConfigSections = append(vmConfigSections, component.SummarySection{
				Header:  "Memory",
				Content: component.NewText(vm.Spec.Template.Spec.Domain.Memory.Guest.String()),
			})
		}
	}

	if len(vm.Spec.Template.Spec.Domain.Devices.Disks) > 0 {
		diskTable := component.NewTable("Disks", "", component.NewTableCols("Name", "Device", "Bus"))
		diskTable.Sort("Name")

		for _, disk := range vm.Spec.Template.Spec.Domain.Devices.Disks {
			diskRow := component.TableRow{
				"Name": component.NewText(disk.Name),
			}

			var device string
			var bus kubevirtv1.DiskBus
			switch {
			case disk.Disk != nil:
				device = "Disk"
				bus = disk.Disk.Bus
			case disk.LUN != nil:
				device = "LUN"
				bus = disk.LUN.Bus
			case disk.CDRom != nil:
				device = "CR-ROM"
				bus = disk.CDRom.Bus
			}

			diskRow["Device"] = component.NewText(device)
			diskRow["Bus"] = component.NewText(string(bus))
			diskTable.Add(diskRow)
		}

		vmConfigSections = append(vmConfigSections, component.SummarySection{
			Header:  "Disks",
			Content: diskTable,
		})
	}

	if len(vm.Spec.Template.Spec.Domain.Devices.Interfaces) > 0 {
		ifaceTable := component.NewTable("Interfaces", "", component.NewTableCols("Name", "Binding Method", "Model", "MAC Address"))
		ifaceTable.Sort("Name")

		for _, iface := range vm.Spec.Template.Spec.Domain.Devices.Interfaces {
			ifaceRow := component.TableRow{
				"Name":        component.NewText(iface.Name),
				"Model":       component.NewText(iface.Model),
				"MAC Address": component.NewText(iface.MacAddress),
			}

			var bindingMethod string
			switch {
			case iface.Bridge != nil:
				bindingMethod = "Bridge"
			case iface.Slirp != nil:
				bindingMethod = "Slirp"
			case iface.Masquerade != nil:
				bindingMethod = "Masquerade"
			case iface.SRIOV != nil:
				bindingMethod = "SRIOV"
			case iface.Macvtap != nil:
				bindingMethod = "Macvtap"
			}

			ifaceRow["Binding Method"] = component.NewText(bindingMethod)
			ifaceTable.Add(ifaceRow)
		}

		vmConfigSections = append(vmConfigSections, component.SummarySection{
			Header:  "Interfaces",
			Content: ifaceTable,
		})
	}

	var vmStatusSections []component.SummarySection
	if vm.Status.Created {
		unstructuredVMI, err := request.DashboardClient.Get(request.Context(), store.Key{
			APIVersion: vmiGVK.GroupVersion().String(),
			Kind:       vmiGVK.Kind,
			Name:       vm.Name,
			Namespace:  vm.Namespace,
		})
		if err != nil {
			return plugin.PrintResponse{}, fmt.Errorf("get VMI: %s", err)
		}

		var vmi kubevirtv1.VirtualMachineInstance
		if err := scheme.Convert(unstructuredVMI, &vmi, request.Context()); err != nil {
			return plugin.PrintResponse{}, fmt.Errorf("convert VMI: %s", err)
		}

		nodePath := fmt.Sprintf("/cluster-overview/nodes/%s", vmi.Status.NodeName)
		vmStatusSections = append(vmStatusSections, component.SummarySection{
			Header:  "Node",
			Content: component.NewLink(vmi.Status.NodeName, vmi.Status.NodeName, nodePath),
		})
	}

	vmPayload := map[string]interface{}{
		"apiVersion": vmGVK.GroupVersion().String(),
		"kind":       vmGVK.Kind,
		"name":       vm.Name,
		"namespace":  vm.Namespace,
	}

	vmAccessButtonGroup := component.NewButtonGroup()
	vmAccessButtonGroup.AddButton(component.NewButton("Open Console", action.CreatePayload(actionVMOpenConsole, vmPayload)))
	if vm.Status.Ready {
		vmStatusSections = append(vmStatusSections, component.SummarySection{
			Header:  "Access",
			Content: vmAccessButtonGroup,
		})
	}

	startVMButton := component.NewButton("Start", action.CreatePayload(actionVMStart, vmPayload))
	stopVMButton := component.NewButton("Stop", action.CreatePayload(actionVMStop, vmPayload))
	pauseVMButton := component.NewButton("Pause", action.CreatePayload(actionVMPause, vmPayload))
	unpauseVMButton := component.NewButton("Unpause", action.CreatePayload(actionVMUnpause, vmPayload))
	restartVMButton := component.NewButton("Restart", action.CreatePayload(actionVMRestart, vmPayload))
	softRebootVMButton := component.NewButton("Soft Reboot", action.CreatePayload(actionVMSoftReboot, vmPayload))

	vmControlButtonGroup := component.NewButtonGroup()
	switch vm.Status.PrintableStatus {
	case kubevirtv1.VirtualMachineStatusStopped:
		vmControlButtonGroup.AddButton(startVMButton)
	case kubevirtv1.VirtualMachineStatusRunning:
		vmControlButtonGroup.AddButton(stopVMButton)
		vmControlButtonGroup.AddButton(pauseVMButton)
		vmControlButtonGroup.AddButton(restartVMButton)
		vmControlButtonGroup.AddButton(softRebootVMButton)
	case kubevirtv1.VirtualMachineStatusPaused:
		vmControlButtonGroup.AddButton(stopVMButton)
		vmControlButtonGroup.AddButton(unpauseVMButton)
		vmControlButtonGroup.AddButton(restartVMButton)
	case kubevirtv1.VirtualMachineStatusCrashLoopBackOff:
		vmControlButtonGroup.AddButton(stopVMButton)
	}

	vmStatusSections = append(vmStatusSections, component.SummarySection{
		Header:  "Control",
		Content: vmControlButtonGroup,
	})

	volumesTable := component.NewTable("Volumes", "VM has no volume.", component.NewTableCols("Name", "Kind", "Description"))
	volumesTable.Sort("Name")
	for _, volume := range vm.Spec.Template.Spec.Volumes {
		volumeRow := component.TableRow{
			"Name": component.NewText(volume.Name),
		}

		var kind string
		var source interface{}
		switch {
		case volume.HostDisk != nil:
			kind = "HostDisk"
			source = volume.HostDisk
		case volume.PersistentVolumeClaim != nil:
			kind = "PersistentVolumeClaim"
			source = volume.PersistentVolumeClaim
		case volume.CloudInitNoCloud != nil:
			kind = "CloudInitNoCloud"
			source = volume.CloudInitNoCloud
		case volume.CloudInitConfigDrive != nil:
			kind = "CloudInitConfigDrive"
			source = volume.CloudInitConfigDrive
		case volume.Sysprep != nil:
			kind = "Sysprep"
			source = volume.Sysprep
		case volume.ContainerDisk != nil:
			kind = "ContainerDisk"
			source = volume.ContainerDisk
		case volume.Ephemeral != nil:
			kind = "Ephemeral"
			source = volume.Ephemeral
		case volume.EmptyDisk != nil:
			kind = "EmptyDisk"
			source = volume.EmptyDisk
		case volume.DataVolume != nil:
			kind = "DataVolume"
			source = volume.DataVolume
		case volume.ConfigMap != nil:
			kind = "ConfigMap"
			source = volume.ConfigMap
		case volume.Secret != nil:
			kind = "Secret"
			source = volume.Secret
		case volume.DownwardAPI != nil:
			kind = "DownwardAPI"
			source = volume.DownwardAPI
		case volume.ServiceAccount != nil:
			kind = "ServiceAccount"
			source = volume.ServiceAccount
		case volume.DownwardMetrics != nil:
			kind = "DownwardMetrics"
			source = volume.DownwardMetrics
		}

		volumeRow["Kind"] = component.NewText(kind)

		sourceJSON, err := json.Marshal(source)
		if err != nil {
			return plugin.PrintResponse{}, fmt.Errorf("marshal volume source: %s", err)
		}
		volumeRow["Description"] = component.NewText(string(sourceJSON))

		volumesTable.Add(volumeRow)
	}

	networksTable := component.NewTable("Networks", "VM has no network.", component.NewTableCols("Name", "Kind", "Description"))
	networksTable.Sort("Name")
	for _, network := range vm.Spec.Template.Spec.Networks {
		networkRow := component.TableRow{
			"Name": component.NewText(network.Name),
		}

		var kind string
		var source interface{}
		switch {
		case network.Pod != nil:
			kind = "Pod"
			source = network.Pod
		case network.Multus != nil:
			kind = "Multus"
			source = network.Multus
		}

		networkRow["Kind"] = component.NewText(kind)

		sourceJSON, err := json.Marshal(source)
		if err != nil {
			return plugin.PrintResponse{}, fmt.Errorf("marshal network source: %s", err)
		}
		networkRow["Description"] = component.NewText(string(sourceJSON))

		networksTable.Add(networkRow)
	}

	return plugin.PrintResponse{
		Config: vmConfigSections,
		Status: vmStatusSections,
		Items: []component.FlexLayoutItem{{
			Width: component.WidthHalf,
			View:  volumesTable,
		}, {
			Width: component.WidthHalf,
			View:  networksTable,
		}},
	}, nil
}

// handleNavigation creates a navigation tree for this plugin. Navigation is dynamic and will
// be called frequently from Octant. Navigation is a tree of `Navigation` structs.
// The plugin can use whatever paths it likes since these paths can be namespaced to the plugin.
func handleNavigation(request *service.NavigationRequest) (navigation.Navigation, error) {
	return navigation.Navigation{
		Title:    "KubeVirt Overview",
		IconName: "cloud",
		Path:     request.GeneratePath(),
		Children: []navigation.Navigation{{
			Title:    "Virtual Machines",
			IconName: "vm",
			Path:     request.GeneratePath("Virtual Machines"),
		}},
	}, nil
}

// handleAction creates an action handler for this plugin. Actions send
// a payload which are used to execute some task
func handleAction(request *service.ActionRequest) error {
	vmKey, err := store.KeyFromPayload(request.Payload)
	if err != nil {
		return fmt.Errorf("get VM key from payload: %s", err)
	}

	if request.ActionName == actionVMOpenConsole {
		if err := exec.Command("virtctl", "vnc", "--namespace", vmKey.Namespace, vmKey.Name).Start(); err != nil {
			return fmt.Errorf("open VNC: %s", err)
		}
		return nil
	}

	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get user home dir: %s", err)
	}

	// TODO: get kubeconfig from Octant?
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(userHomeDir, ".kube", "config"))
	if err != nil {
		return fmt.Errorf("build client config: %s", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Info(err.Error())
		return fmt.Errorf("create client: %s", err)
	}

	var resource string
	var subresource string
	var alertPrefix string
	switch request.ActionName {
	case actionVMStart:
		resource = "virtualmachines"
		subresource = "start"
		alertPrefix = "Starting"
	case actionVMStop:
		resource = "virtualmachines"
		subresource = "stop"
		alertPrefix = "Stopping"
	case actionVMPause:
		resource = "virtualmachineinstances"
		subresource = "pause"
		alertPrefix = "Pausing"
	case actionVMUnpause:
		resource = "virtualmachineinstances"
		subresource = "unpause"
		alertPrefix = "Unpausing"
	case actionVMRestart:
		resource = "virtualmachines"
		subresource = "restart"
		alertPrefix = "Restarting"
	case actionVMSoftReboot:
		resource = "virtualmachineinstances"
		subresource = "softreboot"
		alertPrefix = "Soft Rebooting"
	}

	if subresource != "" {
		if err := client.RESTClient().Put().AbsPath("apis", kubevirtSubresourceGroup, kubevirtVersion).
			Namespace(vmKey.Namespace).Resource(resource).Name(vmKey.Name).SubResource(subresource).Do(request.Context()).Error(); err != nil {
			request.DashboardClient.SendAlert(request.Context(), request.ClientState.ClientID(),
				action.CreateAlert(action.AlertTypeError, err.Error(), action.DefaultAlertExpiration))
			return fmt.Errorf("%s VM: %s", subresource, err)
		}
		request.DashboardClient.SendAlert(request.Context(), request.ClientState.ClientID(), action.CreateAlert(action.AlertTypeInfo,
			fmt.Sprintf("%s %s (%s) %s in %s", alertPrefix, vmKey.Kind, vmKey.APIVersion, vmKey.Name, vmKey.Namespace), action.DefaultAlertExpiration))
	}
	return nil
}

// initRoutes routes for this plugin. In this example, there is a global catch all route
// that will return the content for every single path.
func initRoutes(router *service.Router) {
	router.HandleFunc("*", func(request service.Request) (component.ContentResponse, error) {
		contentResponse := component.NewContentResponse(component.TitleFromString("Virtual Machines"))

		vmTable := component.NewTable("Virtual Machines", "We couldn't find any virtual machines!",
			component.NewTableCols("Name", "Labels", "Ready", "Status", "Node", "Age"))
		vmTable.Sort("Name")

		// TODO: get selected namespace?
		unstructuredVMList, err := request.DashboardClient().List(request.Context(), store.Key{
			APIVersion: vmGVK.GroupVersion().String(),
			Kind:       vmGVK.Kind,
			Namespace:  "default",
		})
		if err != nil {
			return *contentResponse, fmt.Errorf("list VMs: %s", err)
		}

		for i := range unstructuredVMList.Items {
			var vm kubevirtv1.VirtualMachine
			if err := scheme.Convert(&unstructuredVMList.Items[i], &vm, request.Context()); err != nil {
				return *contentResponse, fmt.Errorf("convert VM: %s", err)
			}

			vmPath := fmt.Sprintf("/overview/namespace/%s/custom-resources/virtualmachines.%s/%s", vm.Namespace, vmGVK.GroupVersion().String(), vm.Name)
			vmActionPayload := action.CreatePayload("", map[string]interface{}{
				"apiVersion": vmGVK.GroupVersion().String(),
				"kind":       vmGVK.Kind,
				"name":       vm.Name,
				"namespace":  vm.Namespace,
			})
			vmLink := component.NewLink(vm.Name, vm.Name, vmPath)

			var vmActions []component.GridAction
			if vm.Status.Ready {
				vmActions = append(vmActions, component.GridAction{
					Name:       "Open Console",
					ActionPath: actionVMOpenConsole,
					Payload:    vmActionPayload,
				})
			}

			startVMAction := component.GridAction{
				Name:       "Start",
				ActionPath: actionVMStart,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}
			stopVMAction := component.GridAction{
				Name:       "Stop",
				ActionPath: actionVMStop,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}
			pauseVMAction := component.GridAction{
				Name:       "Pause",
				ActionPath: actionVMPause,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}
			unpauseVMAction := component.GridAction{
				Name:       "Unpause",
				ActionPath: actionVMUnpause,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}
			restartVMAction := component.GridAction{
				Name:       "Restart",
				ActionPath: actionVMRestart,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}
			softRebootVMAction := component.GridAction{
				Name:       "Soft Reboot",
				ActionPath: actionVMSoftReboot,
				Payload:    vmActionPayload,
				Type:       component.GridActionDanger,
			}

			var vmLinkTextStatus component.TextStatus
			switch vm.Status.PrintableStatus {
			case kubevirtv1.VirtualMachineStatusStopped:
				vmActions = append(vmActions, startVMAction)
			case kubevirtv1.VirtualMachineStatusRunning:
				vmLinkTextStatus = component.TextStatusOK
				vmActions = append(vmActions, stopVMAction, pauseVMAction, restartVMAction, softRebootVMAction)
			case kubevirtv1.VirtualMachineStatusPaused:
				vmLinkTextStatus = component.TextStatusWarning
				vmActions = append(vmActions, stopVMAction, unpauseVMAction, restartVMAction)
			case kubevirtv1.VirtualMachineStatusCrashLoopBackOff:
				vmLinkTextStatus = component.TextStatusError
				vmActions = append(vmActions, stopVMAction)
			}

			if vmLinkTextStatus != 0 {
				vmLink.SetStatus(vmLinkTextStatus, component.NewText(string(vm.Status.PrintableStatus)))
			}

			vmRow := component.TableRow{
				"Name":   vmLink,
				"Labels": component.NewLabels(vm.Labels),
				"Ready":  component.NewText(fmt.Sprintf("%v", vm.Status.Ready)),
				"Status": component.NewText(string(vm.Status.PrintableStatus)),
				"Age":    component.NewTimestamp(vm.CreationTimestamp.Time),
			}

			for _, action := range vmActions {
				vmRow.AddAction(action)
			}

			if vm.Status.Created {
				unstructuredVMI, err := request.DashboardClient().Get(request.Context(), store.Key{
					APIVersion: vmiGVK.GroupVersion().String(),
					Kind:       vmiGVK.Kind,
					Name:       vm.Name,
					Namespace:  vm.Namespace,
				})
				if err != nil {
					return *contentResponse, fmt.Errorf("get VMI: %s", err)
				}

				var vmi kubevirtv1.VirtualMachineInstance
				if err := scheme.Convert(unstructuredVMI, &vmi, request.Context()); err != nil {
					return *contentResponse, fmt.Errorf("convert VMI: %s", err)
				}

				nodePath := fmt.Sprintf("/cluster-overview/nodes/%s", vmi.Status.NodeName)
				vmRow["Node"] = component.NewLink(vmi.Status.NodeName, vmi.Status.NodeName, nodePath)
			}

			vmTable.Add(vmRow)
		}

		contentResponse.Add(vmTable)
		return *contentResponse, nil
	})
}
