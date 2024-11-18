package datastore

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"

	"code.cloudfoundry.org/lib/serial"
)

type Options func(container *Container) error

//go:generate counterfeiter -o ../fakes/locker.go --fake-name Locker . locker
type locker interface {
	Lock() error
	Unlock() error
}

//go:generate counterfeiter -o ../fakes/datastore.go --fake-name Datastore . Datastore
type Datastore interface {
	Add(handle, ip string, metadata map[string]interface{}) error
	Delete(handle string) (Container, error)
	ReadAll() (map[string]Container, error)
}

type Container struct {
	Handle   string                 `json:"handle"`
	IP       string                 `json:"ip"`
	IPv6     string                 `json:"ipv6"`
	Metadata map[string]interface{} `json:"metadata"`
}

type Store struct {
	Serializer      serial.Serializer
	Locker          locker
	DataFilePath    string
	VersionFilePath string
	LockedFilePath  string
	CacheMutex      *sync.RWMutex
	FileOwner       string
	FileGroup       string
	cachedVersion   int
	cachedPool      map[string]Container
}

func validate(handle, ip string) error {
	if handle == "" {
		return fmt.Errorf("invalid handle")
	}

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ip: %v", ip)
	}
	return nil
}

func (c *Store) Update(handle, ip string, metadata map[string]interface{}) error {
	return c.AddOrUpdate(handle, ip, metadata, true)
}

func (c *Store) Add(handle, ip string, metadata map[string]interface{}, options ...Options) error {
	return c.AddOrUpdate(handle, ip, metadata, false, options...)
}

func (c *Store) AddOrUpdate(handle, ip string, metadata map[string]interface{}, update bool, options ...Options) error {
	if err := validate(handle, ip); err != nil {
		return err
	}

	err := c.Locker.Lock()
	if err != nil {
		return fmt.Errorf("lock: %s", err)
	}

	defer c.Locker.Unlock()

	dataFile, err := os.OpenFile(c.DataFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open data file: %s", err)
	}

	defer dataFile.Close()

	pool := make(map[string]*Container)

	err = c.Serializer.DecodeAll(dataFile, &pool)
	if err != nil {
		return fmt.Errorf("decoding file: %s", err)
	}

	_, ok := pool[handle]
	if !ok && update {
		return fmt.Errorf("entry does not exist")
	}

	pool[handle] = &Container{
		Handle:   handle,
		IP:       ip,
		Metadata: metadata,
	}

	for _, opt := range options {
		err = opt(pool[handle])
		if err != nil {
			return fmt.Errorf("applying option for ipv6: %s", err)
		}
	}

	err = c.Serializer.EncodeAndOverwrite(dataFile, pool)
	if err != nil {
		return fmt.Errorf("encode and overwrite: %s", err)
	}

	err = c.updateVersion()
	if err != nil {
		return err
	}

	return c.ensureFileOwnership()
}

func WithIPv6(ipv6 string) Options {
	return func(container *Container) error {
		if !validateIPv6(container.IPv6) {
			return fmt.Errorf("invalid ip: %v", ipv6)
		}

		container.IPv6 = ipv6

		return nil
	}
}

func (c *Store) ensureFileOwnership() error {
	if c.FileOwner == "" || c.FileGroup == "" {
		return nil
	}
	uid, gid, err := c.lookupFileOwnerUIDandGID()
	if err != nil {
		return err
	}

	err = os.Chown(c.LockedFilePath, uid, gid)
	if err != nil {
		return err
	}

	err = os.Chown(c.DataFilePath, uid, gid)
	if err != nil {
		return err
	}

	err = os.Chown(c.VersionFilePath, uid, gid)
	if err != nil {
		return err
	}

	return nil
}

func (c *Store) lookupFileOwnerUIDandGID() (int, int, error) {
	fileOwnerUser, err := user.Lookup(c.FileOwner)
	if err != nil {
		return 0, 0, err
	}

	fileOwnerGroup, err := user.LookupGroup(c.FileGroup)
	if err != nil {
		return 0, 0, err
	}

	uid, err := strconv.Atoi(fileOwnerUser.Uid)
	if err != nil {
		return 0, 0, err
	}

	gid, err := strconv.Atoi(fileOwnerGroup.Gid)
	if err != nil {
		return 0, 0, err
	}

	return uid, gid, nil
}

func (c *Store) Delete(handle string) (Container, error) {
	deleted := Container{}
	if handle == "" {
		return deleted, fmt.Errorf("invalid handle")
	}

	err := c.Locker.Lock()
	if err != nil {
		return deleted, fmt.Errorf("lock: %s", err)
	}
	defer c.Locker.Unlock()

	dataFile, err := os.OpenFile(c.DataFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return deleted, fmt.Errorf("open data file: %s", err)
	}
	defer dataFile.Close()

	pool := make(map[string]Container)
	err = c.Serializer.DecodeAll(dataFile, &pool)
	if err != nil {
		return deleted, fmt.Errorf("decoding file: %s", err)
	}

	deleted = pool[handle]

	delete(pool, handle)

	err = c.Serializer.EncodeAndOverwrite(dataFile, pool)
	if err != nil {
		return deleted, fmt.Errorf("encode and overwrite: %s", err)
	}

	err = c.updateVersion()
	if err != nil {
		return deleted, err
	}

	return deleted, c.ensureFileOwnership()
}

func (c *Store) ReadAll() (map[string]Container, error) {
	currentVersion, err := c.currentVersion()
	if err != nil {
		return nil, err
	}

	c.CacheMutex.RLock()
	if currentVersion == c.cachedVersion {
		pool := c.cachedPool
		c.CacheMutex.RUnlock()
		return pool, nil
	}
	c.CacheMutex.RUnlock()

	err = c.Locker.Lock()
	if err != nil {
		return nil, fmt.Errorf("lock: %s", err)
	}
	defer c.Locker.Unlock()

	dataFile, err := os.OpenFile(c.DataFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open data file: %s", err)
	}
	defer dataFile.Close()

	pool := make(map[string]Container)
	err = c.Serializer.DecodeAll(dataFile, &pool)
	if err != nil {
		return nil, fmt.Errorf("decoding file: %s", err)
	}

	// untested
	// we want to get the version again while we have the store locked
	currentVersion, err = c.currentVersion()
	if err != nil {
		return nil, err
	}

	c.CacheMutex.Lock()
	defer c.CacheMutex.Unlock()
	c.cachedPool = pool
	c.cachedVersion = currentVersion

	return pool, nil
}

func (c *Store) updateVersion() error {
	version, err := c.currentVersion()
	if err != nil {
		return err
	}
	err = os.WriteFile(c.VersionFilePath, []byte(strconv.Itoa(version+1)), 0600)
	if err != nil {
		// not tested
		return fmt.Errorf("write version file: %s", err)
	}

	return nil
}

func (c *Store) currentVersion() (int, error) {
	version := 1
	versionFile, err := os.OpenFile(c.VersionFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return version, fmt.Errorf("open version file: %s", err)
	}
	defer versionFile.Close()

	versionContents, err := io.ReadAll(versionFile)
	if err != nil {
		// not tested
		return version, fmt.Errorf("open version file: %s", err)
	}

	if string(versionContents) != "" {
		version, err = strconv.Atoi(string(versionContents))
		if err != nil {
			return version, fmt.Errorf("version file: '%s' is not a number", versionContents)
		}
	}
	return version, err
}

func validateIPv6(ip string) bool {
	ipv6 := net.ParseIP(ip)
	if ipv6 == nil {
		return false
	}

	if ipv6.To4() == nil && ipv6.To16() != nil {
		return true
	}

	return false
}
