// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package main

import (
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	networkingV1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func runIngressWatcher() error {
	log.Info("Starting to watch k8s ingress")

	_, ingressController := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.WatcherClient().NetworkingV1().RESTClient(), "ingresses", v1.NamespaceAll, fields.Everything()),
		&networkingV1.Ingress{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.WithField("ingress", obj).Info("ingress added")
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.WithFields(logrus.Fields{
					"old-ingress": oldObj,
					"new-ingress": newObj,
				}).Info("ingress updated")
			},
			DeleteFunc: func(obj interface{}) {
				log.WithField("ingress", obj).Info("ingress deleted")
			},
		},
		nil,
	)
	go ingressController.Run(wait.NeverStop)
	return nil
}
