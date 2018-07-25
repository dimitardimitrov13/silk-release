package main

import (
	"flag"
	"fmt"
	"log"
	"netmon/config"
	"netmon/poller"
	"os"
	"time"

	"code.cloudfoundry.org/cf-networking-helpers/runner"
	"code.cloudfoundry.org/filelock"
	"code.cloudfoundry.org/lager"
	"github.com/cloudfoundry/dropsonde"
	"github.com/coreos/go-iptables/iptables"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
	"lib/rules"
	"os/exec"
	"sync"
)

var (
	logPrefix = "cfnetworking"
)

func main() {
	configFilePath := flag.String("config-file", "", "path to config file")
	flag.Parse()
	conf, err := config.New(*configFilePath)
	if err != nil {
		log.Fatalf("%s.netmon: reading config: %s", logPrefix, err)
	}

	if conf.LogPrefix != "" {
		logPrefix = conf.LogPrefix
	}

	logger := lager.NewLogger(fmt.Sprintf("%s.netmon", logPrefix))
	sink := lager.NewReconfigurableSink(lager.NewWriterSink(os.Stdout, lager.DEBUG), lager.DEBUG)
	logger.RegisterSink(sink)
	logger.Info("parsed-config", lager.Data{"config": conf})

	logLevel, err := conf.ParseLogLevel()
	if err != nil {
		logger.Fatal("parsing-log-level", err)
	}

	sink.SetMinLevel(logLevel)

	pollInterval := time.Duration(conf.PollInterval) * time.Second
	if pollInterval == 0 {
		pollInterval = time.Second
	}

	ipt, err := iptables.New()
	if err != nil {
		logger.Fatal("iptables-new", err)
	}

	iptLocker := &filelock.Locker{
		FileLocker: filelock.NewLocker(conf.IPTablesLockFile),
		Mutex:      &sync.Mutex{},
	}
	restorer := &rules.Restorer{}

	executablePath, err := exec.LookPath("iptables")
	if err != nil {
		logger.Fatal("commandrunner-new", err)
	}

	iptablesCommandRunner := runner.CommandRunner{
		Executable: executablePath,
	}

	lockedIPTables := &rules.LockedIPTables{
		IPTables:       ipt,
		Locker:         iptLocker,
		Restorer:       restorer,
		IPTablesRunner: iptablesCommandRunner,
	}

	dropsonde.Initialize(conf.MetronAddress, "netmon")
	systemMetrics := &poller.SystemMetrics{
		Logger:          logger,
		PollInterval:    pollInterval,
		InterfaceName:   conf.InterfaceName,
		IPTablesAdapter: lockedIPTables,
	}

	members := grouper.Members{
		{"metric_poller", systemMetrics},
	}

	monitor := ifrit.Invoke(sigmon.New(grouper.NewOrdered(os.Interrupt, members)))
	logger.Info("starting")
	err = <-monitor.Wait()
	if err != nil {
		logger.Fatal("ifrit monitor", err)
	}
}
