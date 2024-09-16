/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	apparmorapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	pbv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	reconcileTimeout = 1 * time.Minute
	dsWait           = 30 * time.Second
)

var (
	ErrNoOwnerProfile   = errors.New("no owner profile defined for this status")
	ErrUnknownOwnerKind = errors.New("the node status owner is of an unknown kind")
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &StatusReconciler{}
}

// A StatusReconciler monitors node changes and updates the profile status.
type StatusReconciler struct {
	client client.Client
	log    logr.Logger
	record record.EventRecorder
}

// Name returns the name of the controller.
func (r *StatusReconciler) Name() string {
	return "nodestatus"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *StatusReconciler) SchemeBuilder() *scheme.Builder {
	return statusv1alpha1.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *StatusReconciler) Healthz(*http.Request) error {
	return nil
}

// Security Profiles Operator RBAC permissions to manage SelinuxProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=delete;get;update;patch

// Security Profiles Operator RBAC permissions to manage SeccompProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch

// Security Profiles Operator RBAC permissions to manage Node Statuses
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile reconciles a NodeStatus.
func (r *StatusReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("nodeStatus", req.Name, "namespace", req.Namespace)
	logger.V(config.VerboseLevel).Info("Reconciling node status")

	logger.Info(fmt.Sprintf("Fetching NodeStatus instance for: %s/%s", req.Namespace, req.Name))
	instance := &statusv1alpha1.SecurityProfileNodeStatus{}
	if err := r.client.Get(ctx, req.NamespacedName, instance); err != nil {
		logger.Info("NodeStatus instance not found, skipping reconciliation")
		return reconcile.Result{}, util.IgnoreNotFound(err)
	}

	logger.Info(fmt.Sprintf("Fetching profile associated with NodeStatus: %s", req.Name))
	prof, getProfErr := r.getProfileFromStatus(ctx, instance)
	if getProfErr != nil {
		logger.Info("Failed to get profile from NodeStatus")
		return reconcile.Result{}, getProfErr
	}

	lprof := logger.WithValues(
		"Profile.Name", prof.GetName(),
		"Profile.Namespace", prof.GetNamespace(),
		"Profile.Kind", prof.GetObjectKind().GroupVersionKind(),
	)

	if prof.GetStatusBase().Status == "" {
		logger.Info("Initializing profile status")
		targetStatus := statusv1alpha1.ProfileStatePending
		if instance.Status != "" {
			targetStatus = instance.Status
		}
		logger.Info(fmt.Sprintf("Target status initialized as: %s", targetStatus))
		return reconcile.Result{}, r.reconcileStatus(ctx, prof, targetStatus, lprof)
	}

	logger.Info("Verifying profile label on the NodeStatus")
	profLabel := instance.Labels[statusv1alpha1.StatusToProfLabel]
	if profLabel == "" {
		logger.Info("Profile label missing on NodeStatus, cannot proceed")
		return reconcile.Result{}, errors.New("unlabeled node status")
	}
	if util.KindBasedDNSLengthName(prof) != profLabel {
		logger.Info("Mismatch between profile label and NodeStatus owner")
		return reconcile.Result{}, errors.New("status doesn't match owner")
	}

	logger.Info(fmt.Sprintf("Listing all node statuses for profile: %s", profLabel))
	nodeStatusList, err := listStatusesForProfile(ctx, r.client, instance.Namespace, profLabel)
	if err != nil {
		logger.Info("Failed to list node statuses")
		return reconcile.Result{}, fmt.Errorf("cannot list the node statuses: %w", err)
	}

	logger.Info("Fetching DaemonSet for Security Profile Operator")
	spodDS, err := r.getDS(ctx, config.GetOperatorNamespace(), lprof)
	if err != nil {
		logger.Info("Failed to get DaemonSet")
		return reconcile.Result{}, fmt.Errorf("cannot get the DS: %w", err)
	}

	if !daemonSetIsReady(spodDS) || daemonSetIsUpdating(spodDS) {
		logger.Info("DaemonSet is either not ready or updating, skipping status update")
		return reconcile.Result{RequeueAfter: dsWait}, nil
	}

	logger.Info("Checking if all node statuses are ready")
	hasStatuses := len(nodeStatusList.Items)
	wantsStatuses := spodDS.Status.DesiredNumberScheduled
	if wantsStatuses > int32(hasStatuses) {
		logger.Info(fmt.Sprintf("Not all node statuses are ready. Has: %d, Wants: %d", hasStatuses, wantsStatuses))
		return reconcile.Result{}, nil
	} else if wantsStatuses < int32(hasStatuses) {
		logger.Info(fmt.Sprintf("Extra node statuses detected. Has: %d, Wants: %d", hasStatuses, wantsStatuses))
		nodeName, err := r.removeStatusForDeletedNode(ctx, nodeStatusList, lprof)
		if err != nil {
			logger.Info("Failed to remove extra statuses")
			return reconcile.Result{}, fmt.Errorf("cannot remove extra statuses: %w", err)
		}
		if nodeName != "" {
			logger.Info(fmt.Sprintf("Removing finalizer from profile for node: %s", nodeName))
			if err := util.RemoveFinalizer(ctx, r.client, prof, util.GetFinalizerNodeString(nodeName)); err != nil {
				logger.Info("Failed to remove finalizer from profile")
				return reconcile.Result{}, fmt.Errorf("cannot remove finalizer from profile: %w", err)
			}
		}
		return reconcile.Result{Requeue: true}, nil
	}

	logger.Info("Comparing node statuses and profile finalizers")
	statusMatch, err := util.FinalizersMatchCurrentNodes(ctx, nodeStatusList)
	if err != nil {
		logger.Info("Failed to compare statuses and finalizers")
		return reconcile.Result{}, fmt.Errorf("cannot compare statuses and finalizers: %w", err)
	}
	if !statusMatch {
		logger.Info("Mismatch found between finalizers and current nodes")
		currentNodeNames, err := util.GetNodeList(ctx)
		if err != nil {
			logger.Info("Failed to fetch current node list")
			return reconcile.Result{}, fmt.Errorf("cannot get node list: %w", err)
		}

		for i := range nodeStatusList.Items {
			nodeStatus := &nodeStatusList.Items[i]
			if !util.ContainsSubstring(currentNodeNames, nodeStatus.NodeName) {
				finalizerNodeString := util.GetFinalizerNodeString(nodeStatus.NodeName)
				logger.Info(fmt.Sprintf("Removing finalizer for non-existent node: %s", nodeStatus.NodeName))
				if err := util.RemoveFinalizer(ctx, r.client, prof, finalizerNodeString); err != nil {
					logger.Info("Failed to remove finalizer for non-existent node")
					return reconcile.Result{}, fmt.Errorf("cannot remove finalizer: %w", err)
				}
			}
		}
	}

	logger.Info("Determining lowest common status among nodes")
	lowestCommonState := statusv1alpha1.LowestState
	for i := range nodeStatusList.Items {
		lowestCommonState = statusv1alpha1.LowerOfTwoStates(lowestCommonState, nodeStatusList.Items[i].Status)
	}
	logger.Info(fmt.Sprintf("Setting profile status to: %s", lowestCommonState))

	return reconcile.Result{}, r.reconcileStatus(ctx, prof, lowestCommonState, lprof)
}

// removeStatusForDeletedNode removes the status for a node that has been deleted.
func (r *StatusReconciler) removeStatusForDeletedNode(ctx context.Context,
	nodeStatusList *statusv1alpha1.SecurityProfileNodeStatusList, logger logr.Logger,
) (string, error) {
	for i := range nodeStatusList.Items {
		nodeName := nodeStatusList.Items[i].NodeName
		node := &v1.Node{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
			if util.IsNotFoundOrConflict(err) {
				logger.Info("Removing node status for removed node", "node", nodeName)
				if err := r.client.Delete(ctx, &nodeStatusList.Items[i]); err != nil {
					return "", fmt.Errorf("cannot delete node status: %w", err)
				}
				return nodeName, nil
			}
			return "", fmt.Errorf("cannot get node: %w", err)
		}
	}
	return "", nil
}

func (r *StatusReconciler) getDS(ctx context.Context, namespace string, l logr.Logger) (*appsv1.DaemonSet, error) {
	// Create a label selector to filter DaemonSets
	dsSelect := labels.NewSelector()
	spodDSFilter, err := labels.NewRequirement("spod", selection.Exists, []string{})
	if err != nil {
		l.Error(err, "Cannot create DS list label")
		return nil, fmt.Errorf("cannot create DS list label: %w", err)
	}
	dsSelect.Add(*spodDSFilter)

	// Log the constructed label selector
	l.Info("Constructed label selector", "selector", dsSelect.String())

	dsListOpts := client.ListOptions{
		LabelSelector: dsSelect,
		Namespace:     namespace,
	}

	// List DaemonSets in the specified namespace
	spodDSList := appsv1.DaemonSetList{}
	if err := r.client.List(ctx, &spodDSList, &dsListOpts); err != nil {
		l.Error(err, "Error listing DaemonSets")
		return nil, fmt.Errorf("cannot list DS: %w", err)
	}

	// Log the number of DaemonSets found
	l.Info("Number of DaemonSets found", "count", len(spodDSList.Items))

	// Check if exactly one DaemonSet is found
	if len(spodDSList.Items) != 1 {
		retErr := errors.New("did not find exactly one DaemonSet")
		l.Error(retErr, "Expected to find 1 DaemonSet", "count", len(spodDSList.Items))
		return nil, fmt.Errorf("listing DS: %w", retErr)
	}

	// Log details of the found DaemonSet
	l.Info("Found DaemonSet", "name", spodDSList.Items[0].Name, "namespace", namespace)
	return &spodDSList.Items[0], nil
}

func (r *StatusReconciler) getProfileFromStatus(
	ctx context.Context,
	s *statusv1alpha1.SecurityProfileNodeStatus,
) (pbv1alpha1.StatusBaseUser, error) {
	ctrl := metav1.GetControllerOf(s)
	if ctrl == nil {
		return nil, fmt.Errorf("getting owner profile: %w", ErrNoOwnerProfile)
	}

	key := types.NamespacedName{
		Name:      ctrl.Name,
		Namespace: s.GetNamespace(),
	}
	var prof pbv1alpha1.StatusBaseUser
	switch ctrl.Kind {
	case "SeccompProfile":
		prof = &seccompprofileapi.SeccompProfile{}
	case "SelinuxProfile":
		prof = &selxv1alpha2.SelinuxProfile{}
	case "RawSelinuxProfile":
		prof = &selxv1alpha2.RawSelinuxProfile{}
	case "AppArmorProfile":
		prof = &apparmorapi.AppArmorProfile{}
	default:
		return nil, fmt.Errorf("getting owner profile: %w", ErrUnknownOwnerKind)
	}
	if err := r.client.Get(ctx, key, prof); err != nil {
		return nil, fmt.Errorf("getting owner profile: %s/%s: %w", s.GetNamespace(), ctrl.Name, err)
	}
	return prof, nil
}

func (r *StatusReconciler) reconcileStatus(
	ctx context.Context,
	prof pbv1alpha1.StatusBaseUser,
	state statusv1alpha1.ProfileState,
	l logr.Logger,
) error {
	pCopy := prof.DeepCopyToStatusBaseIf()

	// We always set this status
	pCopy.SetImplementationStatus()

	outStatus := pCopy.GetStatusBase()
	switch state {
	case statusv1alpha1.ProfileStatePending, "":
		outStatus.Status = statusv1alpha1.ProfileStatePending
		outStatus.SetConditions(spodv1alpha1.Creating())
	case statusv1alpha1.ProfileStateInProgress:
		outStatus.SetConditions(spodv1alpha1.Creating())
		outStatus.Status = statusv1alpha1.ProfileStateInProgress
	case statusv1alpha1.ProfileStateInstalled:
		outStatus.Status = statusv1alpha1.ProfileStateInstalled
		outStatus.SetConditions(spodv1alpha1.Available())
	case statusv1alpha1.ProfileStateTerminating:
		outStatus.Status = statusv1alpha1.ProfileStateTerminating
		outStatus.SetConditions(spodv1alpha1.Deleting())
	case statusv1alpha1.ProfileStateError:
		outStatus.Status = statusv1alpha1.ProfileStateError
		outStatus.SetConditions(spodv1alpha1.Unavailable())
	case statusv1alpha1.ProfileStatePartial:
		outStatus.Status = statusv1alpha1.ProfileStatePartial
		outStatus.SetConditions(spodv1alpha1.Unavailable())
	case statusv1alpha1.ProfileStateDisabled:
		outStatus.Status = statusv1alpha1.ProfileStateDisabled
		outStatus.SetConditions(spodv1alpha1.Unavailable())
	}

	l.V(config.VerboseLevel).Info("Updating status")
	if updateErr := r.client.Status().Update(ctx, pCopy); updateErr != nil {
		return fmt.Errorf("updating policy status: %w", updateErr)
	}

	return nil
}

func daemonSetIsReady(ds *appsv1.DaemonSet) bool {
	return ds.Status.DesiredNumberScheduled > 0 && ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable
}

func daemonSetIsUpdating(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled > 0 &&
		(ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled || ds.Status.NumberUnavailable > 0)
}

func listStatusesForProfile(
	ctx context.Context, c client.Client, namespace string, labelVal string,
) (*statusv1alpha1.SecurityProfileNodeStatusList, error) {
	statusSelect := labels.NewSelector()
	statusFilter, err := labels.NewRequirement(statusv1alpha1.StatusToProfLabel, selection.Equals, []string{labelVal})
	if err != nil {
		return nil, fmt.Errorf("cannot create node status list label: %w", err)
	}
	statusSelect = statusSelect.Add(*statusFilter)
	statusListOpts := client.ListOptions{
		LabelSelector: statusSelect,
		Namespace:     namespace,
	}

	statusList := statusv1alpha1.SecurityProfileNodeStatusList{}
	if err := c.List(ctx, &statusList, &statusListOpts); err != nil {
		return nil, fmt.Errorf("listing statuses: %w", err)
	}

	return &statusList, nil
}
