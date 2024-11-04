package handlers

import (
	"fmt"
	"net/http"

	"code.cloudfoundry.org/cf-networking-helpers/marshal"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/silk/controller"
)

//go:generate counterfeiter -o fakes/lease_repository.go --fake-name LeaseRepository . leaseRepository
type leaseRepository interface {
	RoutableLeases() ([]controller.Lease, error)
}

type LeasesIndex struct {
	Marshaler       marshal.Marshaler
	LeaseRepository leaseRepository
	ErrorResponse   errorResponse
}

func (l *LeasesIndex) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-index")

	leases, err := l.LeaseRepository.RoutableLeases()
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("all-routable-leases: %s", err.Error()))
		return
	}

	response := struct {
		Leases []controller.Lease `json:"leases"`
	}{leases}
	bytes, err := l.Marshaler.Marshal(response)
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("marshal-response: %s", err.Error()))
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write(bytes)
}

//go:generate counterfeiter -o fakes/lease_repository.go --fake-name Lease6Repository . leaseRepository
type lease6Repository interface {
	RoutableLeases6() ([]controller.Lease, error)
}

type Leases6Index struct {
	Marshaler       marshal.Marshaler
	LeaseRepository lease6Repository
	ErrorResponse   errorResponse
}

func (l *Leases6Index) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-ipv6-index")

	leases, err := l.LeaseRepository.RoutableLeases6()
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("all-routable-leases: %s", err.Error()))
		return
	}

	response := struct {
		Leases []controller.Lease `json:"leases"`
	}{leases}
	bytes, err := l.Marshaler.Marshal(response)
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("marshal-response: %s", err.Error()))
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write(bytes)
}
