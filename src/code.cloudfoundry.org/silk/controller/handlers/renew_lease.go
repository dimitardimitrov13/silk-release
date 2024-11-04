package handlers

import (
	"fmt"
	"io"
	"net/http"

	"code.cloudfoundry.org/cf-networking-helpers/marshal"
	"code.cloudfoundry.org/lager/v3"
	"code.cloudfoundry.org/silk/controller"
)

//go:generate counterfeiter -o fakes/lease_renewer.go --fake-name LeaseRenewer . leaseRenewer
type leaseRenewer interface {
	RenewSubnetLease(lease controller.Lease) error
}

//go:generate counterfeiter -o fakes/error_response.go --fake-name ErrorResponse . errorResponse
type errorResponse interface {
	InternalServerError(lager.Logger, http.ResponseWriter, error, string)
	BadRequest(lager.Logger, http.ResponseWriter, error, string)
	Conflict(lager.Logger, http.ResponseWriter, error, string)
}

type RenewLease struct {
	Unmarshaler   marshal.Unmarshaler
	LeaseRenewer  leaseRenewer
	ErrorResponse errorResponse
}

func (l *RenewLease) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-renew")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("read-body: %s", err.Error()))
		return
	}

	var lease controller.Lease
	err = l.Unmarshaler.Unmarshal(bodyBytes, &lease)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("unmarshal-request: %s", err.Error()))
		return
	}

	err = l.LeaseRenewer.RenewSubnetLease(lease)
	if err != nil {
		if _, ok := err.(controller.NonRetriableError); ok {
			l.ErrorResponse.Conflict(logger, w, err, fmt.Sprintf("renew-subnet-lease: %s", err.Error()))
			return
		}

		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("renew-subnet-lease: %s", err.Error()))
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write([]byte("{}"))
}

//go:generate counterfeiter -o fakes/lease_renewer.go --fake-name Lease6Renewer . lease6Renewer
type lease6Renewer interface {
	RenewSubnetLease6(lease controller.Lease) error
}

type RenewLease6 struct {
	Unmarshaler   marshal.Unmarshaler
	LeaseRenewer  lease6Renewer
	ErrorResponse errorResponse
}

func (l *RenewLease6) ServeHTTP(logger lager.Logger, w http.ResponseWriter, req *http.Request) {
	logger = logger.Session("leases-renew")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("read-body: %s", err.Error()))
		return
	}

	var lease controller.Lease
	err = l.Unmarshaler.Unmarshal(bodyBytes, &lease)
	if err != nil {
		l.ErrorResponse.BadRequest(logger, w, err, fmt.Sprintf("unmarshal-request: %s", err.Error()))
		return
	}

	err = l.LeaseRenewer.RenewSubnetLease6(lease)
	if err != nil {
		if _, ok := err.(controller.NonRetriableError); ok {
			l.ErrorResponse.Conflict(logger, w, err, fmt.Sprintf("renew-subnet-lease: %s", err.Error()))
			return
		}

		l.ErrorResponse.InternalServerError(logger, w, err, fmt.Sprintf("renew-subnet-lease: %s", err.Error()))
		return
	}

	// #nosec G104 - ignore errors when writing HTTP responses so we don't spam our logs during a DoS
	w.Write([]byte("{}"))
}
