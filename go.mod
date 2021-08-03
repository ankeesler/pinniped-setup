module github.com/ankeesler/pinniped-setup

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/jetstack/cert-manager v1.4.2
	go.pinniped.dev v0.10.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3 // indirect
	k8s.io/klog v1.0.0 // indirect
	sigs.k8s.io/controller-runtime v0.9.5
)
