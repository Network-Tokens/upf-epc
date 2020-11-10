package main

import (
	"context"
	"log"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"ntf_pb"
)

type ntfConfigEntry struct {
	dpid              uint32
	upf               *upf
	appId             uint32
	encryptionKey     string
	dscp              uint32
	configured		  bool
}

type NtfConfigSet struct {
	configs map[uint32]*ntfConfigEntry
	upf     *upf
	dpid    uint32
}

func NewNtfConfigSet(upf *upf, dpid uint32) *NtfConfigSet {
	log.Println("NewNtfConfigSet")
	config := new(NtfConfigSet)
	config.configs = make(map[uint32]*ntfConfigEntry)
	config.upf = upf
	config.dpid = dpid
	return config
}

func NewNtfConfigEntry(upf *upf, dpid uint32, appId uint32) *ntfConfigEntry {
	log.Println("NewNtfConfigEntry")
	entry := new(ntfConfigEntry)
	entry.appId = appId
	entry.upf = upf
	entry.dpid = dpid
	return entry
}

func (entry *ntfConfigEntry) updateState() {
	log.Println("ntfConfigEntry.updateState()")
	ready := entry.encryptionKey != "" && entry.dscp > 0
	if !entry.configured {
		log.Println(" - not configured yet")
		if ready {
			log.Println(" - configuring...")
			entry.createBessEntry(entry.upf)
		} else {
			log.Println(" - incomplete...")
		}
	} else {
		log.Println(" - already configured")
		if ready {
			log.Println(" - updating...")
			entry.updateBessEntry(entry.upf)
		} else {
			log.Println(" - removing...")
			entry.deleteBessEntry(entry.upf)
		}
	}
}

func (config *ntfConfigEntry) setDSCP(dscp uint32) {
	log.Println("ntfConfigEntry.setDSCP()")
	config.dscp = dscp
	config.updateState()
}

func (config *ntfConfigEntry) setEncryptionKey(encryptionKey string) {
	log.Println("ntfConfigEntry.setEncryptionKey()")
	config.encryptionKey = encryptionKey
	config.updateState()
}

func (config *NtfConfigSet) UpdateAppEncryptionKey(appId uint32, encryptionKey string) {
	log.Println("NtfConfigSet.UpdateAppEncryptionKey()")
	entry, ok := config.configs[appId]
	if !ok {
		entry = NewNtfConfigEntry(config.upf, config.dpid, appId)
		config.configs[appId] = entry
	}

	entry.setEncryptionKey(encryptionKey)
}

func (config *NtfConfigSet) UpdateAppDSCP(appId uint32, dscp uint32) {
	log.Println("NtfConfigSet.UpdateAppDSCP()")
	entry, ok := config.configs[appId]
	if !ok {
		entry = NewNtfConfigEntry(config.upf, appId, config.dpid)
		config.configs[appId] = entry
	}

	entry.setDSCP(dscp)
}

func (config *ntfConfigEntry) createBessEntry(upf *upf) error {
	log.Println("ntfConfigEntry.createBessEntry(config.appId=", config.appId, ")")
	if err := upf.pauseAll(); err != nil {
		return err
	}

	token := ntf_pb.UserCentricNetworkToken{
		AppId:         config.appId,
		EncryptionKey: config.encryptionKey,
	}

	arg := ntf_pb.NtfEntryCreateArg{
		Dpid: config.dpid,
		Token: &token,
		Options: &ntf_pb.NtfEntryCreateArg_Dscp{config.dscp},
	}

	any, err := ptypes.MarshalAny(&arg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cr, err := upf.client.ModuleCommand(ctx, &pb.CommandRequest{
		Name: "ntf0",
		Cmd:  "entry_create",
		Arg:  any,
	})
	log.Println("entry_create:", cr)

	if err != nil {
		return err
	}
	log.Println("ntf.entry_create():", cr)

	if err = upf.resumeAll(); err != nil {
		return err
	}

	return nil
}

type ntfError struct {
	reason string
}

func (e *ntfError) Error() string {
	return e.reason
}

func (config *ntfConfigEntry) updateBessEntry(upf *upf) error {
	log.Println("TODO: updateBessEntry")
	return &ntfError{ "TODO" }
}

func (config *ntfConfigEntry) deleteBessEntry(upf *upf) error {
	log.Println("TODO: deleteBessEntry")
	return &ntfError{ "TODO" }
}
