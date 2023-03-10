
local sett_do_register = minetest.settings:get_bool("secure.dsroles.do_register", true)
local sett_init_default = minetest.settings:get_bool("secure.dsroles.init_default", true)
if not sett_do_register then
	sett_init_default = false
end
local sett_deinstall = minetest.settings:get_bool("secure.dsroles.deinstall", false)
assert(not (sett_deinstall and sett_do_register))
local sett_chatcommands = minetest.settings:get_bool("secure.dsroles.chatcommands", true)
assert(not (sett_deinstall and sett_chatcommands))

dsroles = {}

-- Terminology:
-- * privilege, aka. priv:
--   A minetest priv, or its name.
-- * player:
--   A minetest player, or its name.
-- * role:
--   Used to group privs.
-- * polymorphic role, aka. PRole, aka. prole:
--   Any of:
--   * priv prole
--   * role prole
--   * player prole
--   A (non-priv) prole can inherit other (non-player) proles.
-- * priv prole:
--   A priv, but prefixed with "priv_", e.g. "priv_shout".
-- * role prole:
--   A role, but prefixed with "role_", e.g. "role_moderator".
-- * player prole:
--   A playername, but prefixed with "player_", e.g. "player_singleplayer".

local function escape_str(str)
--[[
	local t = {}
	local start = 1
	for i = 1, #str do
		local b = str:byte(i, i)
		if not ((0x30 <= b and b <= 0x39) -- 0-9
				or (0x41 <= b and b <= 0x5a) -- A-Z
				or (0x61 <= b and b <= 0x7a) -- a-z
				) then
			if i > start then
				table.insert(t, std:sub(start, i-1))
			end
			start = i+1
			table.insert(t, string.format("%%%.2x", b))
		end
	end
	table.insert(t, std:sub(start, i-1))
	return table.concat(t)
]]
	return (string.gsub(str, "([^A-Za-z0-9])", function(s)
			return string.format("%%%.2x", string.byte(s))
		end))
end

local function unescape_str(str)
	return (string.gsub(str, "%%(..)", function(s)
			return string.char(tonumber(s, 16))
		end))
end

function dsroles.prole_is_priv(p)
	return p:sub(1, 5) == "priv_"
end
function dsroles.prole_is_role(p)
	return p:sub(1, 5) == "role_"
end
function dsroles.prole_is_player(p)
	return p:sub(1, 7) == "player_"
end

function dsroles.prole_to_priv(p)
	return dsroles.prole_is_priv(p) and unescape_str(p:sub(6))
end
function dsroles.prole_to_role(p)
	return dsroles.prole_is_role(p) and unescape_str(p:sub(6))
end
function dsroles.prole_to_player(p)
	return dsroles.prole_is_player(p) and unescape_str(p:sub(8))
end

function dsroles.priv_to_prole(name)
	return "priv_"..escape_str(name)
end
function dsroles.role_to_prole(name)
	return "role_"..escape_str(name)
end
function dsroles.player_to_prole(name)
	return "player_"..escape_str(name)
end

local modstorage = minetest.get_mod_storage()

local privilege_cache = setmetatable({}, {__mode = "k"})

local old_mt_notify_authentication_modified = minetest.notify_authentication_modified
minetest.notify_authentication_modified = function(name)
	if name then
		privilege_cache[name] = nil
	else
		privilege_cache = setmetatable({}, {__mode = "k"})
	end
	return old_mt_notify_authentication_modified(name)
end

dsroles.modstorage_prole_db = {
	-- Returns: {
	--   inherits = {prole, ..},
	-- }
	get_prole_entry = function(prolename)
		local strval = modstorage:get(prolename)
		if not strval then
			return nil
		else
			return minetest.deserialize(strval)
		end
	end,

	delete_prole_entry = function(prolename)
		modstorage:set_string(prolename, "")

		if dsroles.prole_is_role(prolename) then
			local list_role_proles = dsroles.modstorage_prole_db.get_list_role_proles()
			for i = 1, #list_role_proles do
				if list_role_proles[i] == prolename then
					list_role_proles[i] = list_role_proles[#list_role_proles]
					list_role_proles[#list_role_proles] = nil
				end
			end
			modstorage:set_string("list_role_proles", minetest.serialize(list_role_proles))
		end
	end,

	set_prole_entry_unchecked = function(prolename, prole_entry)
		modstorage:set_string(prolename, minetest.serialize(prole_entry))

		if dsroles.prole_is_role(prolename) and
				not dsroles.modstorage_prole_db.get_prole_entry(prolename) then
			local list_role_proles = dsroles.modstorage_prole_db.get_list_role_proles()
			table.insert(list_role_proles, prolename)
			modstorage:set_string("list_role_proles", minetest.serialize(list_role_proles))
		end
	end,

	set_prole_entry = function(prolename, prole_entry)
		if type(prole_entry) ~= "table" or type(prole_entry.inherits) ~= "table" then
			return false, "type error"
		end
		if dsroles.prole_is_priv(prolename) then
			-- must not inherit
			if #prole_entry.inherits ~= 0 then
				return false, "priv prole must not inherit"
			end
		elseif not dsroles.prole_is_role(prolename)
				and not dsroles.prole_is_player(prolename) then
			return false, string.format("not a prole: '%s'", prolename)
		end
		-- may only inherit priv or role proles
		for _, inh in ipairs(prole_entry.inherits) do
			assert(dsroles.prole_is_priv(inh) or dsroles.prole_is_role(inh))
		end
		-- check for cycles
		local all_inherited = dsroles.modstorage_prole_db
				.get_all_inherited(prole_entry.inherits, {prolename})
		for _, p in ipairs(all_inherited) do
			if p == prolename then
				return false, "cycle detected"
			end
		end

		dsroles.modstorage_prole_db.set_prole_entry_unchecked(prolename, prole_entry)
		return true
	end,

	-- All recursively inherited proles
	get_all_inherited = function(prolenames, ignore)
		local seen = {}
		local working_set = {}
		local ret = {}

		for _, p in ipairs(prolenames) do
			table.insert(working_set, p)
			seen[p] = true
		end
		for _, p in ipairs(ignore or {}) do
			seen[p] = true
		end

		while #working_set ~= 0 do
			local p = table.remove(working_set)
			table.insert(ret, p)

			local prole_entry = dsroles.modstorage_prole_db.get_prole_entry(p)
			local inherits = prole_entry and prole_entry.inherits or {}

			for _, inh in ipairs(inherits) do
				if not seen[inh] then
					table.insert(working_set, inh)
					seen[inh] = true
				end
			end
		end

		return ret
	end,

	-- returns list of privs (not proles)
	get_privs = function(prolename)
		local plname = dsroles.prole_to_player(prolename)
		if plname and privilege_cache[plname] then
			return privilege_cache[plname]
		end

		local all_inherited = dsroles.modstorage_prole_db.get_all_inherited({prolename})
		local privs = {}
		for _, p in ipairs(all_inherited) do
			local priv = dsroles.prole_to_priv(p)
			if priv then
				table.insert(privs, priv)
			end
		end

		if plname then
			privilege_cache[plname] = privs
		end
		return privs
	end,

	-- Reloads. Like auth_handler.reload().
	reload = function()
		-- no-op
	end,

	get_list_role_proles = function()
		return minetest.deserialize(modstorage:get("list_role_proles") or "{}")
	end,
}

-- same as in builtin auth handler, required per lua api
local function add_forced_privs(privileges, name)
	if minetest.is_singleplayer() then
		for priv, def in pairs(minetest.registered_privileges) do
			if def.give_to_singleplayer then
				privileges[priv] = true
			end
		end
	elseif name == minetest.settings:get("name") then
		for priv, def in pairs(minetest.registered_privileges) do
			if def.give_to_admin then
				privileges[priv] = true
			end
		end
	end
end

function dsroles.make_auth_handler(base_auth_handler, prole_db)
	-- if new player, old_privileges is nil
	local function create_or_migrate_plprole_entry(name, old_privileges)
		local inherits = old_privileges and dsroles.on_migrate_player(name, old_privileges)
				or dsroles.on_new_player(name)

		local plprole = dsroles.player_to_prole(name)
		local succ, errmsg = prole_db.set_prole_entry(plprole,
				{inherits = inherits})
		if not succ then
			minetest.log("error", string.format(
					"[dsroles] creating proles entry for '%s' failed ('%s'). creating un-roled player",
					name, errmsg))
			assert(prole_db.set_prole_entry(plprole, {inherits = {}}))
		end
	end

	local function create_plprole_entry_if_nonexistent(name, where)
		local prole_entry = prole_db.get_prole_entry(dsroles.player_to_prole(name))
		if prole_entry then
			minetest.log("info", string.format(
					"[dsroles] %s: creating proles entry for '%s'",
					where, name))
			create_or_migrate_plprole_entry(name,
					(base_auth_handler.get_auth(name) or {}).privileges)
		end
	end

	return {
		get_auth = function(name)
			local auth_entry = base_auth_handler.get_auth(name)
			if not auth_entry then
				return nil
			end

			create_plprole_entry_if_nonexistent(name, "get_auth")
			local priv_list = prole_db.get_privs(dsroles.player_to_prole(name))
			local privileges = {}
			for _, priv in ipairs(priv_list) do
				privileges[priv] = true
			end
			add_forced_privs(privileges, name)

			return {
				password = auth_entry.password,
				privileges = privileges,
				last_login = auth_entry.last_login,
			}
		end,

		create_auth = function(name, password)
			local created_entry = base_auth_handler.create_auth(name, password)

			if created_entry then
				minetest.log("info", string.format(
						"[dsroles] create_auth: creating proles entry for '%s'",
						name))
				create_or_migrate_plprole_entry(name)
			end
			minetest.notify_authentication_modified(name)
			return created_entry
		end,

		delete_auth = function(name)
			local succ = base_auth_handler.delete_auth(name)

			if succ then
				minetest.log("info", string.format("[dsroles] delete_auth: deleting entry of '%s'", name))
				prole_db.delete_prole_entry(dsroles.player_to_prole(name))
			end
			minetest.notify_authentication_modified(name)
			return succ
		end,

		set_password = function(name, password)
			local succ = base_auth_handler.set_password(name, password)

			if succ then
				create_plprole_entry_if_nonexistent(name, "set_password")
			end
			minetest.notify_authentication_modified(name)
		end,

		set_privileges = function(name, privileges)
			local succ = base_auth_handler.set_privileges(name, privileges)

			if succ then
				create_plprole_entry_if_nonexistent(name, "set_privileges")
			end
			minetest.notify_authentication_modified(name)
			dsroles.on_set_privileges(name, privileges)
			return succ
		end,

		reload = function()
			-- Our modstorage doesn't need to be reloaded.
			-- (This function is weird anyway. Only the file db backend implements
			-- this (to reload its file). I guess the intended use-case is to
			-- sync between multiple servers.)
			base_auth_handler.reload()
			prole_db.reload()
		end,

		record_login = function(name)
			return base_auth_handler.record_login(name)
		end,

		iterate = function()
			return base_auth_handler.iterate()
		end,

		dsroles_iterate_roles = function()
			local roles = {}
			local list_role_proles = prole_db.get_list_role_proles()
			for _, roprole in ipairs(list_role_proles) do
				roles[dsroles.prole_to_role(roprole)] = true
			end
			return pairs(roles)
		end,
	}
end

function dsroles.iterate_roles()
	return dsroles.auth_handler.dsroles_iterate_roles()
end

function dsroles.set_prole(prolename, prole_entry)
	dsroles.prole_db.set_prole_entry(prolename, prole_entry)
	local plname = dsroles.prole_to_player() -- if nil, we notify all
	minetest.notify_authentication_modified(plname)
end

-- Override this.
-- Called when a new player is added, who didn't have privs before.
-- Return a list of proles that the player should have.
function dsroles.on_new_player(_name)
	local proles = {dsroles.role_to_prole("new_player_unhandled")}
	local default_privs = minetest.string_to_privs(minetest.settings:get("default_privs"))
	for _, priv in ipairs(default_privs) do
		table.insert(proles, dsroles.priv_to_prole(priv))
	end
	return proles
end

-- Override this.
-- Called when a pre-dsroles player is found and needs to be updated (or when
-- a new player is created with auth_handler.set_privileges().).
-- old_privileges is the privs that the player had before.
-- Return a list of proles that the player should have.
function dsroles.on_migrate_player(_name, old_privileges)
	local proles = {dsroles.role_to_prole("role_old_player_unhandled")}
	for _, priv in ipairs(old_privileges) do
		table.insert(proles, dsroles.priv_to_prole(priv))
	end
	return proles
end

-- Called when set_privileges is used.
-- If not overridden, adds the role directly to the player.
function dsroles.on_set_privileges(name, privileges)
	local old_privs = minetest.get_player_privs()
	local plprole = dsroles.player_to_prole(name)
	local prole_entry = dsroles.prole_db.get_prole_entry(plprole)
	for p in pairs(privileges) do
		if not old_privs[p] then
			table.insert(prole_entry.inherits, dsroles.priv_to_prole(p))
		end
	end
	dsroles.set_prole(plprole, prole_entry)
end


-- register stuff

local is_inited

if sett_do_register then
	local modversion = modstorage.get("version")
	is_inited = modversion ~= nil
	if is_inited and modversion ~= "0.0.1" then
		error("version mismatch: "..modversion)
	end
	modstorage.set_string("version", "0.0.1")

	dsroles.prole_db = dsroles.modstorage_prole_db
	dsroles.auth_handler = dsroles.make_auth_handler(core.builtin_auth_handler, dsroles.prole_db)
	minetest.register_authentication_handler(dsroles.auth_handler)
end

if sett_init_default and not is_inited then
	minetest.log("info", "[dsroles] initing default roles")

	local default_privs_inherits = {}
	local default_privs = minetest.string_to_privs(minetest.settings:get("default_privs"))
	for _, priv in ipairs(default_privs) do
		table.insert(default_privs_inherits, dsroles.priv_to_prole(priv))
	end
	dsroles.set_prole(dsroles.role_to_prole("default_privs"), {inherits = default_privs_inherits})

	dsroles.on_new_player = function(_name)
		return {dsroles.priv_to_prole("default_privs")}
	end

	-- how old players are handled is left to the server owner for now
end

if sett_deinstall then
	minetest.log("info", "[dsroles] deinstall: giving players privs of their former roles")
	local auth_handler = minetest.get_auth_handler()
	for playername in auth_handler.iterate() do
		auth_handler.set_privileges(playername,
				dsroles.modstorage_prole_db.get_privs(dsroles.player_to_prole(playername)))
	end
	minetest.log("info", "[dsroles] deinstall: done. "
			.."To completely remove this mod, also remove the modstorage from the world dir.")
end

-- TODO
--~ if sett_chatcommands then
--~ end

-- TODOs:
-- * chatcommands
-- * formspec
-- * restricted role-changes made by non-admins (i.e. moderator)
-- * on_grant, on_revoke
-- * roles with time-limit
-- * testing
