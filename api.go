// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package linode

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type DatacenterID uint64
type PlanID uint64
type KernelID uint64
type LinodeID uint64
type DistributionID uint64
type DiskID uint64
type ConfigurationID uint64
type JobID uint64

type Client struct {
	key string
}

// Create a new API client with an API key. If empty, pull the API
// key from the environment
func NewClient(apiKey string) Client {
	if apiKey == "" {
		apiKey = os.Getenv("LINODE_APIKEY")
	}

	return Client{
		key: apiKey,
	}
}

func (c *Client) newCall(action string) url.Values {
	p := make(url.Values)
	p.Set("api_action", action)
	p.Set("api_key", c.key)
	return p
}

var ErrDatacenterNotFound = errors.New("Datacenter not found")

// Find a datacenter matching the specified city name
func (c *Client) FindDatacenterByCity(city string) (DatacenterID, error) {
	type datacenterResponse struct {
		ID             DatacenterID `json:"DATACENTERID"`
		AbbrevLocation string       `json:"ABBR"`
	}

	var datacenters []datacenterResponse

	p := c.newCall("avail.datacenters")
	if err := processAPICall(p, &datacenters); err != nil {
		return ^DatacenterID(0), err
	}

	// find datacenter in response
	lcity := strings.ToLower(city)
	for ii := range datacenters {
		if lname := strings.ToLower(datacenters[ii].AbbrevLocation); lname == lcity {
			return datacenters[ii].ID, nil
		}
	}

	return ^DatacenterID(0), ErrDatacenterNotFound
}

var ErrPlanNotFound = errors.New("Plan not found")

// Find a linode plan (machine type) by label
func (c *Client) FindPlanByLabel(label string) (PlanID, error) {
	type planResponse struct {
		Label string `json:"LABEL"`
		ID    PlanID `json:"PLANID"`
	}
	var plans []planResponse

	p := c.newCall("avail.linodeplans")
	if err := processAPICall(p, &plans); err != nil {
		return ^PlanID(0), err
	}

	// find plan in response
	llabel := strings.ToLower(label)
	for ii := range plans {
		if strings.ToLower(plans[ii].Label) == llabel {
			return plans[ii].ID, nil
		}
	}

	return ^PlanID(0), ErrPlanNotFound
}

// Kernel architecture
type KernelType string

const (
	KernelLatest32 = KernelType("Latest 32 bit ")
	KernelLatest64 = KernelType("Latest 64 bit ")
)

var ErrKernelNotFound = errors.New("Kernel not found")

// Find the latest kernel by type
func (c *Client) FindKernel(kernel KernelType) (KernelID, error) {
	type kernelResponse struct {
		ID    KernelID `json:"KERNELID"`
		Label string   `json:"LABEL"`
	}
	var kernels []kernelResponse

	p := c.newCall("avail.kernels")
	if err := processAPICall(p, &kernels); err != nil {
		return ^KernelID(0), err
	}

	// find a matching kernel
	for ii := range kernels {
		if strings.HasPrefix(kernels[ii].Label, string(kernel)) {
			return kernels[ii].ID, nil
		}
	}

	return ^KernelID(0), ErrKernelNotFound
}

var ErrDistributionNotFound = errors.New("Distribution not found")

type DistributionArch int

const (
	Distribution64bit = DistributionArch(1)
	Distribution32but = DistributionArch(0)
)

// Find a distribution by its description
func (c *Client) FindDistribution(arch DistributionArch, desc string) (DistributionID, error) {
	type distroResponse struct {
		Arch  DistributionArch `json:"IS64BIT"`
		Label string           `json:"LABEL"`
		ID    DistributionID   `json:"DISTRIBUTIONID"`
	}
	var distros []distroResponse

	p := c.newCall("avail.distributions")
	if err := processAPICall(p, &distros); err != nil {
		return ^DistributionID(0), err
	}

	ldesc := strings.ToLower(desc)
	for ii := range distros {
		if distros[ii].Arch == arch && strings.ToLower(distros[ii].Label) == ldesc {
			return distros[ii].ID, nil
		}
	}

	return ^DistributionID(0), ErrDistributionNotFound
}

// Create a new hourly Linode machine
func (c *Client) CreateHourlyLinode(datacenter DatacenterID, plan PlanID) (LinodeID, error) {
	var response struct {
		LinodeID LinodeID
	}

	p := c.newCall("linode.create")
	p.Set("DATACENTERID", strconv.FormatUint(uint64(datacenter), 10))
	p.Set("PLANID", strconv.FormatUint(uint64(plan), 10))
	if err := processAPICall(p, &response); err != nil {
		return ^LinodeID(0), err
	}

	return response.LinodeID, nil
}

// Destroy a linode
func (c *Client) DestroyLinode(id LinodeID) error {
	p := c.newCall("linode.delete")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	p.Set("skupChecks", "true")

	if err := processAPICall(p, nil); err != nil {
		return err
	}

	return nil
}

// Pending disk job
type DiskJob struct {
	DiskID DiskID
	JobID  JobID
}

// Create a swap disk for a Linode
func (c *Client) CreateSwapDisk(id LinodeID, sizeMB uint) (DiskJob, error) {
	var job DiskJob

	p := c.newCall("linode.disk.create")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	p.Set("Label", fmt.Sprintf("%dMB Swap Image", sizeMB))
	p.Set("Type", "swap")
	p.Set("Size", strconv.FormatUint(uint64(sizeMB), 10))
	if err := processAPICall(p, &job); err != nil {
		return DiskJob{}, err
	}

	return job, nil
}

// Create a disk from a distribution for a Linode
func (c *Client) CreateDiskFromDistro(id LinodeID, distro DistributionID, sizeMB uint, label, rootSSHKey string) (DiskJob, error) {
	var job DiskJob

	// create a random password
	var key [128]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return DiskJob{}, fmt.Errorf("Failed to create random root password: %v", err)
	}
	rootPassword := base64.URLEncoding.EncodeToString(key[:])
	if len(rootPassword) > 128 {
		rootPassword = rootPassword[:128]
	}

	p := c.newCall("linode.disk.createfromdistribution")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	p.Set("DistributionID", strconv.FormatUint(uint64(distro), 10))
	p.Set("Label", label)
	p.Set("Size", strconv.FormatUint(uint64(sizeMB), 10))
	p.Set("rootPass", rootPassword)
	p.Set("rootSSHKey", rootSSHKey)
	if err := processAPICall(p, &job); err != nil {
		return DiskJob{}, err
	}

	return job, nil
}

// Create a configuration for a Linode
func (c *Client) CreateConfiguration(id LinodeID, kernel KernelID, disks []DiskID) (ConfigurationID, error) {
	var response struct {
		ID ConfigurationID `json:"ConfigID"`
	}

	p := c.newCall("linode.config.create")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	p.Set("KernelID", strconv.FormatUint(uint64(kernel), 10))
	p.Set("Label", "Default Linux Profile")
	if len(disks) > 0 {
		b := new(bytes.Buffer)
		for ii := range disks {
			if ii > 0 {
				b.WriteRune(',')
			}
			b.WriteString(strconv.FormatUint(uint64(disks[ii]), 10))
		}
		p.Set("DiskList", b.String())
		p.Set("RootDeviceNum", "1")
	}
	p.Set("helper_disableUpdateDB", "true")
	p.Set("helper_xen", "true")
	p.Set("helper_depmod", "true")
	p.Set("sevtmpfs_automount", "true")
	if err := processAPICall(p, &response); err != nil {
		return ^ConfigurationID(0), err
	}

	return response.ID, nil
}

func (c *Client) Boot(id LinodeID, config ConfigurationID) (JobID, error) {
	var response struct {
		JobID JobID
	}

	p := c.newCall("linode.boot")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	p.Set("ConfigID", strconv.FormatUint(uint64(config), 10))
	if err := processAPICall(p, &response); err != nil {
		return ^JobID(0), err
	}

	return response.JobID, nil
}

// Add a private IP address to a Linode
func (c *Client) AddPrivateIP(id LinodeID) (string, error) {
	var response struct {
		IPAddress string
	}

	p := c.newCall("linode.ip.addprivate")
	p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
	if err := processAPICall(p, &response); err != nil {
		return "", err
	}

	return response.IPAddress, nil
}

var ErrJobNotFound = errors.New("Job not found")
var ErrJobTimedout = errors.New("Job timedout")

// Wait for a job id to complete
func (c *Client) WaitForJob(id LinodeID, job JobID, sleep, duration time.Duration) error {
	type jobResponse struct {
		CompletedTime string      `json:"HOST_FINISH_DT"`
		HostMessage   string      `json:"HOST_MESSAGE"`
		Success       interface{} `json:"HOST_SUCCESS"`
	}

	getJobStatus := func(pending bool) (jobResponse, error) {
		var jobs []jobResponse

		p := c.newCall("linode.job.list")
		p.Set("LinodeID", strconv.FormatUint(uint64(id), 10))
		p.Set("JobID", strconv.FormatUint(uint64(job), 10))
		if pending {
			p.Set("pendingOnly", "1")
		}
		if err := processAPICall(p, &jobs); err != nil {
			return jobResponse{}, err
		}

		// check results
		if len(jobs) != 1 {
			return jobResponse{}, ErrJobNotFound
		}

		return jobs[0], nil
	}

	// wait for job to complete
	expires := time.Now().Add(duration)
	for {
		if time.Now().After(expires) {
			return ErrJobTimedout
		}

		_, err := getJobStatus(true)
		if err == ErrJobNotFound {
			break
		} else if err != nil {
			return err
		}

		time.Sleep(sleep)
	}

	// check status of the job
	resp, err := getJobStatus(false)
	if err != nil {
		return err
	}

	if f, ok := resp.Success.(float64); !ok || int64(f) != 1 {
		return fmt.Errorf("Job failed: %q", resp.HostMessage)
	}

	return nil
}

// run a Linode API function and parse its result
func processAPICall(p url.Values, outData interface{}) error {
	resp, err := http.PostForm("https://api.linode.com/", p)
	if err != nil {
		return fmt.Errorf("Failed to post: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("API returned non-OK value: %d %q", resp.StatusCode, resp.Status)
	}

	apiResp := struct {
		Errors []struct {
			Code    int64  `json:"ERRORCODE"`
			Message string `json:"ERRORMESSAGE"`
		} `json:"ERRORARRAY"`
		Data interface{} `json:"DATA"`
	}{
		Data: outData,
	}

	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("Failed to decode response: %v", err)
	}

	if len(apiResp.Errors) > 0 {
		b := new(bytes.Buffer)
		for ii := range apiResp.Errors {
			if ii > 0 {
				b.WriteRune(';')
			}
			fmt.Fprintf(b, "%d: %q", apiResp.Errors[ii].Code, apiResp.Errors[ii].Message)
		}
		return errors.New(b.String())
	}

	return nil
}
