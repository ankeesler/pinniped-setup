package main

import (
	"os"

	"github.com/go-logr/logr"
	certmanagerv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	conciergeauthv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
)

// TODO: can we get away without running this on workload clusters? Template in supervisor address?
// TODO: how will this work when Dex is in the mix? Another controller?

type names struct {
	federationDomain     string
	federationDomainCert string
	jwtAuthenticator     string
	supervisorNamespace  string
	conciergeNamespace   string
	service              string
}

type config struct {
	names       names
	clusterType string
	log         logr.Logger
}

func main() {
	// TODO: maybe move this to init?
	klog.InitFlags(nil)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = supervisorconfigv1alpha1.AddToScheme(scheme)
	_ = conciergeauthv1alpha1.AddToScheme(scheme)
	_ = certmanagerv1beta1.AddToScheme(scheme) // TODO: what version of this should we use?

	ctrl.SetLogger(klogr.New())

	// TODO: make these flags
	config := config{
		names: names{
			federationDomain:     "pinniped-federation-domain",
			federationDomainCert: "pinniped-cert",
			jwtAuthenticator:     "tkg-jwt-authenticator",
			supervisorNamespace:  "pinniped-supervisor",
			conciergeNamespace:   "pinniped-concierge",
			service:              "pinniped-supervisor",
		},
		clusterType: "management",
		log:         ctrl.Log.WithName("controller"),
	}

	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Logger: ctrl.Log.WithName("manager"),
		// TODO: other options?
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	if err := addControllersToManager(mgr, &config); err != nil {
		setupLog.Error(err, "error initializing controllers")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func addControllersToManager(mgr ctrl.Manager, config *config) error {
	var errs []error
	errs = append(errs, addPinnipedControllersToManager(mgr, config))
	errs = append(errs, addDexControllersToManager(mgr, config))
	return k8sutilerrors.NewAggregate(errs)
}
