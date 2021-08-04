package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/go-logr/logr"
	certmanagerv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	conciergeauthv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
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
	enqueueRequestsFromServiceRelatedObjects := handler.EnqueueRequestsFromMapFunc(func(o client.Object) []ctrl.Request {
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: config.names.supervisorNamespace, Name: config.names.service}}}
	})

	// It would be great if we could set OwnerReferences on these child objects, but that is hard to
	// do since we want the kapp-controller to deploy them.
	_, err := ctrl.
		NewControllerManagedBy(mgr).
		For(&corev1.Service{}, builder.WithPredicates(newNamespaceNamePredicate(config.names.supervisorNamespace, config.names.service))).
		Watches(
			&source.Kind{Type: &certmanagerv1beta1.Certificate{}},
			enqueueRequestsFromServiceRelatedObjects,
			builder.WithPredicates(newNamespaceNamePredicate(config.names.supervisorNamespace, config.names.federationDomainCert)),
		).
		Watches(
			&source.Kind{Type: &supervisorconfigv1alpha1.FederationDomain{}},
			enqueueRequestsFromServiceRelatedObjects,
			builder.WithPredicates(newNamespaceNamePredicate(config.names.supervisorNamespace, config.names.federationDomain)),
		).
		Watches(
			&source.Kind{Type: &conciergeauthv1alpha1.JWTAuthenticator{}},
			enqueueRequestsFromServiceRelatedObjects,
			builder.WithPredicates(newNamespaceNamePredicate(config.names.conciergeNamespace, config.names.jwtAuthenticator)),
		).
		Build(newController(config, mgr.GetClient()))

	return err
}

func newNamespaceNamePredicate(namespace, name string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == namespace && obj.GetName() == name
	})
}

type controller struct {
	config *config
	client client.Client
}

func newController(config *config, client client.Client) *controller {
	return &controller{config: config, client: client}
}

func (c *controller) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	c.config.log.Info("reconcile called", "namespacesName", req.NamespacedName)

	// Get the service that triggered this reconcile.
	var s corev1.Service
	if err := c.client.Get(ctx, req.NamespacedName, &s); err != nil {
		c.config.log.Error(err, "cannot get service", "serviceNamespacedName", req.NamespacedName)
		return ctrl.Result{}, err
	}
	c.config.log.Info("got service", "serviceNamespacedName", req.NamespacedName, "type", s.Spec.Type)

	// Get the service address to use for the supervisor.
	supervisorHost, supervisorPort, err := c.serviceAddress(ctx, &s)
	if err != nil {
		c.config.log.Error(err, "cannot get service address", "serviceNamespacedName", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Apply the supervisor serving cert.
	supervisorServingCert := makeSupervisorServingCert(c.config, &s)
	appliedCert, err := c.apply(ctx, supervisorServingCert, supervisorHostToCertFunc(supervisorHost))
	if err != nil {
		c.config.log.Error(err, "cannot apply serving cert", "serviceNamespacedName", req.NamespacedName, "certNamespace", supervisorServingCert.GetNamespace(), "certName", supervisorServingCert.GetName())
		return ctrl.Result{}, err
	}
	c.config.log.Info("applied supervisor serving cert", "serviceNamespacedName", req.NamespacedName, "certNamespace", appliedCert.GetNamespace(), "certName", appliedCert.GetName())

	// Get the supervisor serving cert CA.
	// TODO: this variable name is too long.
	supervisorServingCertCAData, err := c.certCAData(ctx, appliedCert.(*certmanagerv1beta1.Certificate))
	if err != nil {
		c.config.log.Error(err, "cannot get cert CA bundle", "serviceNamespacedName", req.NamespacedName)
		return ctrl.Result{}, err
	}

	// Apply the supervisor federation domain.
	federationDomain := makeFederationDomain(c.config, &s)
	appliedFederationDomain, err := c.apply(ctx, federationDomain, supervisorAddressAndCertToFederationDomainFunc(supervisorHost, supervisorPort, appliedCert.(*certmanagerv1beta1.Certificate)))
	if err != nil {
		c.config.log.Error(err, "cannot apply supervisor federation domain", "serviceNamespacedName", req.NamespacedName, "federationDomainNamespace", federationDomain.Namespace, "federationDomainName", federationDomain.Name)
		return ctrl.Result{}, err
	}
	c.config.log.Info("applied supervisor federation domain", "serviceNamespacedName", req.NamespacedName, "namespace", appliedFederationDomain.GetNamespace(), "name", appliedFederationDomain.GetName())

	// Apply the concierge jwt authenticator.
	jwtAuthenticator := makeJWTAuthenticator(c.config, &s)
	appliedJWTAuthenticator, err := c.apply(ctx, jwtAuthenticator, federationDomainAndSupervisorServingCertCADataToJWTAuthenticatorFunc(appliedFederationDomain.(*supervisorconfigv1alpha1.FederationDomain), supervisorServingCertCAData))
	if err != nil {
		c.config.log.Error(err, "cannot create concierge jwt authenticator", "serviceNamespacedName", req.NamespacedName, "jwtAuthenticatorNamespace", jwtAuthenticator.Namespace, "jwtAuthenticatorName", jwtAuthenticator.Name)
		return ctrl.Result{}, err
	}
	c.config.log.Info("applied concierge jwt authenticator", "serviceNamespacedName", req.NamespacedName, "namespace", appliedJWTAuthenticator.GetNamespace(), "name", appliedJWTAuthenticator.GetName())

	return ctrl.Result{}, nil
}

func (c *controller) serviceAddress(ctx context.Context, s *corev1.Service) (string, string, error) {
	ipAddresses, dnsNames, err := c.serviceAddresses(ctx, s)
	if err != nil {
		return "", "", fmt.Errorf("cannot get service addresses: %w", err)
	}

	var address string
	if len(ipAddresses) > 0 {
		address = ipAddresses[0]
	}
	if len(dnsNames) > 0 {
		address = dnsNames[0]
	}

	if len(address) == 0 {
		return "", "", errors.New("did not find any ip or dns addresses")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("cannot split host and port from address %q: %w", address, err)
	}

	return host, port, nil
}

func (c *controller) serviceAddresses(ctx context.Context, s *corev1.Service) ([]string, []string, error) {
	switch s.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		return c.loadBalancerServiceAddresses(s)
	case corev1.ServiceTypeNodePort:
		return c.nodePortServiceAddresses(ctx, s)
	default:
		return nil, nil, fmt.Errorf("cannot get service addresses for type %s", s.Spec.Type)
	}
}

func (c *controller) loadBalancerServiceAddresses(s *corev1.Service) ([]string, []string, error) {
	ipAddresses := []string{}
	dnsNames := []string{}
	for _, ingress := range s.Status.LoadBalancer.Ingress {
		for _, port := range s.Spec.Ports {
			if ingress.IP != "" {
				ipAddresses = append(ipAddresses, net.JoinHostPort(ingress.IP, fmt.Sprintf("%d", port.Port)))
			}
			if ingress.Hostname != "" {
				dnsNames = append(dnsNames, net.JoinHostPort(ingress.Hostname, fmt.Sprintf("%d", port.Port)))
			}
		}
	}
	return ipAddresses, dnsNames, nil
}

func (c *controller) nodePortServiceAddresses(ctx context.Context, s *corev1.Service) ([]string, []string, error) {
	clusterAddress, err := c.clusterAddress(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get cluster address: %w", err)
	}

	ipAddresses := make([]string, len(s.Spec.Ports))
	for i := range s.Spec.Ports {
		ipAddresses[i] = net.JoinHostPort(clusterAddress, fmt.Sprintf("%d", s.Spec.Ports[i].NodePort))
	}

	return ipAddresses, []string{}, nil
}

func (c *controller) clusterAddress(ctx context.Context) (string, error) {
	var clusterInfoCM corev1.ConfigMap
	if err := c.client.Get(ctx, client.ObjectKey{Namespace: "kube-public", Name: "cluster-info"}, &clusterInfoCM); err != nil {
		return "", fmt.Errorf("could not get cluster-info ConfigMap: %w", err)
	}

	kubeconfigData, ok := clusterInfoCM.Data["kubeconfig"]
	if !ok {
		return "", fmt.Errorf("could not get kubeconfig from cluster-info ConfigMap with data %s", clusterInfoCM.Data)
	}

	kubeconfig, err := clientcmd.Load([]byte(kubeconfigData))
	if err != nil {
		return "", fmt.Errorf("could not load kubeconfig from Secret Data: %w", err)
	}

	for _, cluster := range kubeconfig.Clusters {
		serverURL, err := url.Parse(cluster.Server)
		if err != nil {
			return "", fmt.Errorf("failed to parse server URL from kubeconfig: %w", err)
		}
		return serverURL.Hostname(), nil
	}

	return "", errors.New("could not find clusters in kubeconfig")
}

func (c *controller) certCAData(ctx context.Context, cert *certmanagerv1beta1.Certificate) (string, error) {
	secretKey := client.ObjectKey{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	var secret corev1.Secret
	if err := c.client.Get(ctx, secretKey, &secret); err != nil {
		return "", fmt.Errorf("could not get cert Secret %s: %w", secretKey, err)
	}

	caData, ok := secret.Data["ca.crt"]
	if !ok {
		return "", errors.New("did not find 'ca.crt' in Secret data")
	}

	return base64.StdEncoding.EncodeToString(caData), nil
}

func (c *controller) apply(ctx context.Context, obj client.Object, applyFunc func(obj client.Object)) (client.Object, error) {
	objKey := client.ObjectKey{Namespace: obj.GetNamespace(), Name: obj.GetName()}
	err := c.client.Get(ctx, objKey, obj)
	notFound := k8serrors.IsNotFound(err)
	if !notFound && err != nil {
		return nil, fmt.Errorf("could not get object %s: %w", objKey, err)
	}

	newObj := obj.DeepCopyObject().(client.Object)
	applyFunc(newObj)
	c.config.log.Info("applying", "new", notFound, "from", obj, "to", newObj)
	if notFound {
		if err := c.client.Create(ctx, newObj); err != nil {
			return nil, fmt.Errorf("could not create object %s: %w", objKey, err)
		}
	} else {
		if err := c.client.Update(ctx, newObj); err != nil {
			return nil, fmt.Errorf("could not update object %s: %w", objKey, err)
		}
	}

	return obj, nil
}

func makeSupervisorServingCert(config *config, s *corev1.Service) *certmanagerv1beta1.Certificate {
	return &certmanagerv1beta1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.names.supervisorNamespace,
			Name:      config.names.federationDomainCert,
		},
	}
}

func supervisorHostToCertFunc(supervisorHost string) func(obj client.Object) {
	// Note! This code has kinda already been written in the post-deploy job.
	return func(obj client.Object) {
		cert := obj.(*certmanagerv1beta1.Certificate)
		if net.ParseIP(supervisorHost) != nil {
			cert.Spec.IPAddresses = []string{supervisorHost}
		} else {
			cert.Spec.DNSNames = []string{supervisorHost}
		}
	}
}

func makeFederationDomain(config *config, s *corev1.Service) *supervisorconfigv1alpha1.FederationDomain {
	return &supervisorconfigv1alpha1.FederationDomain{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.names.supervisorNamespace,
			Name:      config.names.federationDomain,
		},
	}
}

func supervisorAddressAndCertToFederationDomainFunc(supervisorHost, supervisorPort string, cert *certmanagerv1beta1.Certificate) func(obj client.Object) {
	return func(obj client.Object) {
		federationDomain := obj.(*supervisorconfigv1alpha1.FederationDomain)
		federationDomain.Spec.Issuer = fmt.Sprintf("https://%s:%s", supervisorHost, supervisorPort) // TODO: do we need RemoveDefaultTLSPort?
		federationDomain.Spec.TLS = &supervisorconfigv1alpha1.FederationDomainTLSSpec{SecretName: cert.Spec.SecretName}
	}
}

func makeJWTAuthenticator(config *config, s *corev1.Service) *conciergeauthv1alpha1.JWTAuthenticator {
	return &conciergeauthv1alpha1.JWTAuthenticator{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: config.names.conciergeNamespace,
			Name:      config.names.jwtAuthenticator,
		},
	}
}

// TODO: this function name is too long.
func federationDomainAndSupervisorServingCertCADataToJWTAuthenticatorFunc(federationDomain *supervisorconfigv1alpha1.FederationDomain, supervisorServingCertCAData string) func(obj client.Object) {
	return func(obj client.Object) {
		jwtAuthenticator := obj.(*conciergeauthv1alpha1.JWTAuthenticator)
		jwtAuthenticator.Spec.Issuer = federationDomain.Spec.Issuer
		jwtAuthenticator.Spec.TLS = &conciergeauthv1alpha1.TLSSpec{CertificateAuthorityData: supervisorServingCertCAData}
	}
}
