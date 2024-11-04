package handlers

import (
	"fmt"
	"io"
	"net/http"

	"code.cloudfoundry.org/cf-networking-helpers/marshal"
	"code.cloudfoundry.org/lager/v3"
)

//go:generate counterfeiter -o fakes/lease_releaser.go --fake-name LeaseReleaser . leaseReleaser
type leaseReleaser interface {
	ReleaseSubnetLease(underlayIP string) error
}

type ReleaseLease struct {
	Marshaler     marshal.Marshaler
	Unmarshaler   marshal.Unmarshaler
	LeaseReleaser leaseReleaser
	ErrorResponse errorResponse
}

func (l *ReleaseLease) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-release")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("read-body: %s", err.Error()))
		return
	}

	var payload struct {
		UnderlayIP string `json:"underlay_ip"`
	}
	err = l.Unmarshaler.Unmarshal(bodyBytes, &payload)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("unmarshal-request: %s", err.Error()))
		return
	}

	err = l.LeaseReleaser.ReleaseSubnetLease(payload.UnderlayIP)
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, err.Error())
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write([]byte(`{}`))
}

//go:generate counterfeiter -o fakes/lease_releaser.go --fake-name LeaseReleaser . lease6Releaser
type lease6Releaser interface {
	ReleaseSubnetLease6(underlayIP string) error
}

type ReleaseLease6 struct {
	Marshaler     marshal.Marshaler
	Unmarshaler   marshal.Unmarshaler
	LeaseReleaser lease6Releaser
	ErrorResponse errorResponse
}

func (l *ReleaseLease6) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-release")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("read-body: %s", err.Error()))
		return
	}

	var payload struct {
		UnderlayIP string `json:"underlay_ip"`
	}
	err = l.Unmarshaler.Unmarshal(bodyBytes, &payload)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("unmarshal-request: %s", err.Error()))
		return
	}

	err = l.LeaseReleaser.ReleaseSubnetLease6(payload.UnderlayIP)
	if err != nil {
		l.ErrorResponse.InternalServerError(logger, w, err, err.Error())
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write([]byte(`{}`))
}
