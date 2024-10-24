package kernel

import (
	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("[sig-node][Suite:openshift/nodes/realtime][Disruptive] Real time kernel should allow", g.Ordered, func() {
	defer g.GinkgoRecover()
	var (
		oc = exutil.NewCLI(rtNamespace).AsAdmin()
	)

	g.BeforeAll(func() {
		failIfNotRT(oc)
		configureRealtimeTestEnvironment(oc)
	})

	g.BeforeEach(func() {
		startRtTestPod(oc)
	})

	g.It("pi_stress to run successfully with the default algorithm", func() {
		args := []string{rtPodName, "--", "pi_stress", "--duration=600", "--groups=1"}
		_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "error occured running pi_stress with the fifo algorithm")
	})

	g.It("pi_stress to run successfully with the round robin algorithm", func() {
		args := []string{rtPodName, "--", "pi_stress", "--duration=600", "--groups=1", "--rr"}
		_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "error occured running pi_stress with the round robin algorithm")
	})

	g.It("deadline_test to run successfully", func() {
		args := []string{rtPodName, "--", "deadline_test"}
		_, err := oc.SetNamespace(rtNamespace).Run("exec").Args(args...).Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "error occured running deadline_test")
	})

	g.AfterEach(func() {
		cleanupRtTestPod(oc)
	})

	g.AfterAll(func() {
		cleanupRealtimeTestEnvironment(oc)
	})

})
