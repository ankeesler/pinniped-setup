package main

import (
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func addDexControllersToManager(mgr ctrl.Manager, config *config) error {
	return nil
}

type dexController struct {
	config *config
	client client.Client
}
