/*
 * packet-sensorlab.c
 *
 *		@version 1.0
 *  	@date March , 2016
 *      @author Quentin Lampin <quentin.lampin@orange.com>
 *		Copyright 2015 Orange
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 */

#ifndef __BUILDING_WIRESHARK_DISSECTOR__
#define __BUILDING_WIRESHARK_DISSECTOR__
#endif

#include <stdio.h>
#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <epan/to_str.h>
#include <epan/expert.h>

#include "packet-sensorlab.h"
#include "include/sensorlab-frame-format.h"




static inline guint guint8_hash(gconstpointer  key){
	guint hash;

	hash = (guint)(*((guint8*)key));
	return hash;
}

static inline gboolean guint8_equal(gconstpointer  key1, gconstpointer  key2){
	gboolean result;
	result = (gboolean)(*((guint8*)key1) == *((guint8*)key2));
	return result;
}

static wmem_map_t* node_scope_map;


static gint32 protocol_sensorlab_id = -1;

static gint32 hf_sensorlab_nodeid = -1;
static gint32 hf_sensorlab_eventid = -1;

static gint32 hf_sensorlab_entityid = -1;
static gint32 hf_sensorlab_linkid = -1;
static gint32 hf_sensorlab_frameid = -1;

static gint32 hf_sensorlab_entitynamelength = -1;
static gint32 hf_sensorlab_entityname = -1;

static gint32 hf_sensorlab_propertiescount = -1;
static gint32 hf_sensorlab_sourcepropertiescount = -1;
static gint32 hf_sensorlab_targetpropertiescount = -1;

static gint32 hf_sensorlab_framedatalength = -1;
static gint32 hf_sensorlab_framedata = -1;

static gint32 hf_sensorlab_propertyid = -1;
static gint32 hf_sensorlab_propertyprefix = -1;
static gint32 hf_sensorlab_propertyunit = -1;
static gint32 hf_sensorlab_propertytype = -1;
static gint32 hf_sensorlab_propertynamelength = -1;
static gint32 hf_sensorlab_propertyvaluelength = -1;
static gint32 hf_sensorlab_propertyname = -1;

static gint32 hf_sensorlab_propertyvalueboolean = -1;
static gint32 hf_sensorlab_propertyvalueint8 = -1;
static gint32 hf_sensorlab_propertyvalueint16 = -1;
static gint32 hf_sensorlab_propertyvalueint32 = -1;
static gint32 hf_sensorlab_propertyvalueint64 = -1;
static gint32 hf_sensorlab_propertyvalueuint8 = -1;
static gint32 hf_sensorlab_propertyvalueuint16 = -1;
static gint32 hf_sensorlab_propertyvalueuint32 = -1;
static gint32 hf_sensorlab_propertyvalueuint64 = -1;
static gint32 hf_sensorlab_propertyvaluefloat = -1;
static gint32 hf_sensorlab_propertyvaluedouble = -1;
static gint32 hf_sensorlab_propertyvalueasciiarray= -1;
static gint32 hf_sensorlab_propertyvaluebytearray= -1;



static hf_register_info sensorlab_header_fields[] = {
		{ &hf_sensorlab_nodeid,			{ "Node ID", "sensorlab.nodeID", FT_UINT32, BASE_DEC, NULL, 0x0, "Node ID", HFILL	}						},
		{ &hf_sensorlab_eventid,	        	{ "Event ID", "sensorlab.eventID",FT_UINT8, BASE_HEX, VALS(event_names_dictionary), 0x0, "Event ID", HFILL }				},
		{ &hf_sensorlab_entityid,			{ "Entity ID", "sensorlab.entityID",FT_UINT8, BASE_HEX, NULL, 0x0, "Entity ID (local to the node scope)", HFILL }			},
		{ &hf_sensorlab_linkid,			{ "Link ID", "sensorlab.linkID",FT_UINT8, BASE_HEX, NULL, 0x0, "link ID (local to the node scope)", HFILL }				},
		{ &hf_sensorlab_frameid,			{ "Frame ID", "sensorlab.frameID",FT_UINT8, BASE_HEX, NULL, 0x0, "Frame ID (local to the node scope)", HFILL }				},
		{ &hf_sensorlab_entitynamelength,		{ "Entity Name Length", "sensorlab.entityNameLength",FT_UINT8, BASE_DEC, NULL, 0x0, "Entity Name Length", HFILL }			},
		{ &hf_sensorlab_entityname,			{ "Entity Name", "sensorlab.entityName",FT_STRING, BASE_NONE, NULL, 0x0, "Entity Name", HFILL }						},
		{ &hf_sensorlab_propertiescount,		{ "Properties Count", "sensorlab.propertiesCount",FT_UINT8, BASE_DEC, NULL, 0x0, "Properties Count", HFILL }				},
		{ &hf_sensorlab_sourcepropertiescount,	{ "Source Properties Count", "sensorlab.sourcePropertiesCount",FT_UINT8, BASE_DEC, NULL, 0x0, "Source Properties Count", HFILL }	},
		{ &hf_sensorlab_targetpropertiescount,	{ "Target Properties Count", "sensorlab.targetPropertiesCount",FT_UINT8, BASE_DEC, NULL, 0x0, "Target Properties Count", HFILL }	},
		{ &hf_sensorlab_framedatalength,		{ "Frame Data Length", "sensorlab.frameDataLength",FT_UINT8, BASE_DEC, NULL, 0x0, "Frame Data Length", HFILL }				},
		{ &hf_sensorlab_framedata,			{ "Frame Data", "sensorlab.frameData",FT_BYTES, BASE_NONE, NULL, 0x0, "Frame Data", HFILL }						},
		{ &hf_sensorlab_propertyid,			{ "Property ID", "sensorlab.propertyID",FT_UINT8, BASE_DEC, NULL, 0x0, "Property ID", HFILL }						},
		{ &hf_sensorlab_propertyprefix,		{ "Property Prefix", "sensorlab.propertyPrefix",FT_UINT8, BASE_HEX, VALS(prefix_names_dictionary), 0x0, "Property Prefix", HFILL }	},
		{ &hf_sensorlab_propertyunit,		{ "Property Unit", "sensorlab.propertyUnit",FT_UINT8, BASE_HEX, VALS(unit_names_dictionary), 0x0, "Property Unit", HFILL }		},
		{ &hf_sensorlab_propertytype,		{ "Property Type", "sensorlab.propertyType",FT_UINT8, BASE_HEX, VALS(type_names_dictionary), 0x0, "Property Unit", HFILL }		},
		{ &hf_sensorlab_propertynamelength,		{ "Property Name Length", "sensorlab.propertyNameLength",FT_UINT8, BASE_DEC, NULL, 0x0, "Property Name Length", HFILL }			},
		{ &hf_sensorlab_propertyvaluelength,	{ "Property Value Length", "sensorlab.propertyValueLength",FT_UINT16, BASE_DEC, NULL, 0x0, "Property Name Length", HFILL }		},
		{ &hf_sensorlab_propertyname,		{ "Property Name", "sensorlab.propertyName",FT_STRING, BASE_NONE, NULL, 0x0, "Property Name", HFILL }					},
		{ &hf_sensorlab_propertyvalueboolean,	{ "Property Value", "sensorlab.value",FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Property Value", HFILL }					},
		{ &hf_sensorlab_propertyvalueint8,		{ "Property Value", "sensorlab.value",FT_INT8, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueint16,		{ "Property Value", "sensorlab.value",FT_INT16, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueint32,		{ "Property Value", "sensorlab.value",FT_INT32, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueint64,		{ "Property Value", "sensorlab.value",FT_INT64, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueuint8,		{ "Property Value", "sensorlab.value",FT_UINT8, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueuint16,	{ "Property Value", "sensorlab.value",FT_UINT16, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueuint32,	{ "Property Value", "sensorlab.value",FT_UINT32, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvalueuint64,	{ "Property Value", "sensorlab.value",FT_UINT64, BASE_DEC, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvaluefloat,		{ "Property Value", "sensorlab.value",FT_FLOAT, BASE_NONE, NULL, 0x0, "Property Value", HFILL }						},
		{ &hf_sensorlab_propertyvaluedouble,	{ "Property Value", "sensorlab.value",FT_DOUBLE, BASE_NONE, NULL, 0x0, "Property Value", HFILL }					},
		{ &hf_sensorlab_propertyvalueasciiarray,	{ "Property Value", "sensorlab.value",FT_STRING, BASE_NONE, NULL, 0x0, "Property Value", HFILL }					},
		{ &hf_sensorlab_propertyvaluebytearray,	{ "Property Value", "sensorlab.value",FT_BYTES, BASE_NONE, NULL, 0x0, "Property Value", HFILL }						},
};

expert_module_t* expert_sensorlab;
static expert_field ei_sensorlab_event_id = EI_INIT;
static ei_register_info expert_infos[] = {
	{ &ei_sensorlab_event_id,  { "sensorlab.event_id_unknown", PI_MALFORMED, PI_ERROR, "Event ID Unknown Cannot Dissect", EXPFILL }},
};

static gint32 ett_sensorlab = -1;
static gint32 ett_properties = -1;
static gint32 ett_source_properties = -1;
static gint32 ett_target_properties = -1;
static gint32 ett_frame = -1;
static gint32 * sensorlab_expansion_tree_types[] = {	&ett_sensorlab, &ett_properties, &ett_source_properties, &ett_target_properties, &ett_frame	};

static dissector_handle_t sensorlabs_dissector_handle;

node_scope_s* node_scope_map_insert(guint32 node_id);
node_scope_s* node_scope_map_lookup(guint32 node_id);
entity_scope_s* entity_scope_map_insert(node_scope_s* node_scope, guint8 entity_id, gchar* entity_name);
entity_scope_s* entity_scope_map_lookup(node_scope_s* node_scope, guint8 entity_id);
link_scope_s* link_scope_map_insert(entity_scope_s* entity_scope, guint8 link_id);
link_scope_s* link_scope_map_lookup(entity_scope_s* entity_scope, guint8 link_id);
frame_scope_s* frame_scope_map_insert(node_scope_s* node_scope, guint8 frame_id);
frame_scope_s* frame_scope_map_lookup(node_scope_s* node_scope, guint8 frame_id);

property_summary_s* property_summary_map_insert(wmem_map_t* property_map, guint8 property_id, property_info_s* property_info);
property_summary_s* property_map_lookup(wmem_map_t* property_map, guint8 property_id);

void proto_init_sensorlab(void);
void proto_register_sensorlab(void);
void proto_reg_handoff_sensorlab(void);
static int dissect_sensorlab(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_);


properties_and_offset_s*dissect_property_payloads(guint8 payload_type, tvbuff_t* tvb, packet_info* pinfo, gint32 tvb_offset, guint8 properties_count, wmem_map_t* property_map);

gchar* property_to_INFO_str(property_info_s* property_info);
gchar* property_to_JSON_str(property_info_s* property_info);


node_scope_s*
node_scope_map_insert(guint32 node_id){
	node_scope_s* node_scope;

	node_scope = node_scope_map_lookup(node_id);
	if(node_scope != NULL){
		printf("[error] node scope already declared for %d\n", node_id);
	} else {
		node_scope = (node_scope_s*)wmem_alloc(wmem_file_scope(),sizeof(node_scope_s));
		node_scope->id = node_id;
		node_scope->property_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		node_scope->entity_scope_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		node_scope->frame_scope_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		wmem_map_insert(node_scope_map, &(node_scope->id), node_scope);
	}
	return node_scope;
}

node_scope_s*
node_scope_map_lookup(guint32 node_id){
	node_scope_s* node_scope;

	node_scope = (node_scope_s*)wmem_map_lookup(node_scope_map,&node_id);
	return node_scope;
}

entity_scope_s*
entity_scope_map_insert(node_scope_s* node_scope, guint8 entity_id, gchar* entity_name){
	entity_scope_s* entity_scope;
	entity_scope = NULL;
	if(node_scope != NULL){
		entity_scope = (entity_scope_s*)wmem_alloc(wmem_file_scope(),sizeof(entity_scope_s));
		entity_scope->id = entity_id;
		entity_scope->name = wmem_strdup(wmem_file_scope(), entity_name);
		entity_scope->frame_dissector_name = wmem_strdup_printf(wmem_file_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
		entity_scope->property_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		entity_scope->link_scope_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		wmem_map_insert(node_scope->entity_scope_map, &(entity_scope->id), entity_scope);
	}else{
		printf("[error] node scope is NULL\n");
	}
	return entity_scope;
}

entity_scope_s*
entity_scope_map_lookup(node_scope_s* node_scope, guint8 entity_id){
	entity_scope_s* entity_scope;
	entity_scope = NULL;
	if(node_scope != NULL){
		entity_scope = (entity_scope_s*)wmem_map_lookup(node_scope->entity_scope_map, &entity_id);
	}else{
		printf("[error] node scope is NULL\n");
	}
	return entity_scope;
}

link_scope_s*
link_scope_map_insert(entity_scope_s* entity_scope, guint8 link_id){
	link_scope_s* link_scope;

	link_scope = NULL;
	if(entity_scope != NULL){
		link_scope = (link_scope_s*)wmem_alloc(wmem_file_scope(), sizeof(link_scope_s));
		link_scope->id = link_id;
		link_scope->property_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		wmem_map_insert(entity_scope->link_scope_map, &(link_scope->id), link_scope);
	}else{
		printf("[error] entity scope is NULL\n");
	}
	return link_scope;
}

link_scope_s*
link_scope_map_lookup(entity_scope_s* entity_scope, guint8 link_id){
	link_scope_s* link_scope;
	link_scope = NULL;
	if(entity_scope != NULL){
		link_scope = (link_scope_s*)wmem_map_lookup(entity_scope->link_scope_map, &link_id);
	}else{
		printf("[error] entity scope is NULL\n");
	}
	return link_scope;
}

frame_scope_s*
frame_scope_map_insert(node_scope_s* node_scope, guint8 frame_id){
	frame_scope_s* frame_scope;
	frame_scope = NULL;
	if(node_scope != NULL){
		frame_scope = (frame_scope_s*)wmem_alloc(wmem_file_scope(), sizeof(link_scope_s));
		frame_scope->id = frame_id;
		frame_scope->property_map = wmem_map_new(wmem_file_scope(), guint8_hash, guint8_equal);
		wmem_map_insert(node_scope->frame_scope_map, &(frame_scope->id), frame_scope);
	}else{
		printf("[error] node scope is NULL\n");
	}
	return frame_scope;
}

frame_scope_s*
frame_scope_map_lookup(node_scope_s* node_scope, guint8 frame_id){
	frame_scope_s* frame_scope;
	frame_scope = NULL;
	if(node_scope != NULL){
		frame_scope = (frame_scope_s*)wmem_map_lookup(node_scope->frame_scope_map, &frame_id);
	}else{
		printf("[error] node scope is NULL\n");
	}
	return frame_scope;
}


property_summary_s*
property_summary_map_insert(wmem_map_t* property_map, guint8 property_id, property_info_s* property_info){
	property_summary_s* property_summary;
	property_summary = NULL;
	if(property_map != NULL){
		property_summary = (property_summary_s*)wmem_alloc(wmem_file_scope(),sizeof(property_summary_s));
		property_summary->id =  property_id;
		property_summary->prefix = property_info->prefix;
		property_summary->unit = property_info->unit;
		property_summary->type = property_info->type;
		property_summary->name = wmem_strdup(wmem_file_scope(), property_info->name);
		wmem_map_insert(property_map,&(property_summary->id), property_summary);
	}
	return property_summary;
}

property_summary_s*
property_map_lookup(wmem_map_t* property_map, guint8 property_id){
	property_summary_s* property_summary;
	property_summary = (property_summary_s*)wmem_map_lookup(property_map,&property_id);
	return property_summary;
}

void
proto_init_sensorlab(void){
	node_scope_map = wmem_map_new(wmem_file_scope(),g_int_hash,g_int_equal);
}

void
proto_register_sensorlab(void){
	protocol_sensorlab_id = proto_register_protocol( "sensorlab", "sensorlab", "slab" );
	proto_register_field_array(protocol_sensorlab_id, sensorlab_header_fields, array_length(sensorlab_header_fields));
	proto_register_subtree_array(sensorlab_expansion_tree_types, array_length(sensorlab_expansion_tree_types));
	expert_sensorlab = expert_register_protocol(protocol_sensorlab_id);
	expert_register_field_array(expert_sensorlab, expert_infos, array_length(expert_infos));

	register_init_routine(proto_init_sensorlab);
	register_dissector("sensorlab", dissect_sensorlab, protocol_sensorlab_id);
}

void
proto_reg_handoff_sensorlab(void){
	sensorlabs_dissector_handle = create_dissector_handle(dissect_sensorlab, protocol_sensorlab_id);
	dissector_add_uint("wtap_encap", SENSORLAB_LINK_LAYER_TYPE, sensorlabs_dissector_handle);
}

properties_and_offset_s*
dissect_property_payloads(guint8 payload_type, tvbuff_t* tvb, packet_info* pinfo, gint32 tvb_offset, guint8 properties_count, wmem_map_t* property_map){
	properties_and_offset_s* result;
	property_info_s property_info;
	guint8	property_name_length;
	property_summary_s* property_summary;


	result = (properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
	result->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));

	while (properties_count > 0) {
		switch(payload_type){
		case PROPERTY_DECLARATION_PAYLOAD:
			property_name_length = tvb_get_guint8(tvb, tvb_offset   + 	PROPERTY_DECLARATION_NAME_LENGTH_FIELD);
			property_info.id  = tvb_get_guint8(tvb,          tvb_offset   + 	PROPERTY_DECLARATION_ID_FIELD);
			property_info.prefix = tvb_get_guint8(tvb, tvb_offset   +	PROPERTY_DECLARATION_UNIT_PREFIX_FIELD);
			property_info.unit = tvb_get_guint8(tvb,   tvb_offset   +	PROPERTY_DECLARATION_UNIT_FIELD);
			property_info.type = tvb_get_guint8(tvb,   tvb_offset   +   PROPERTY_DECLARATION_TYPE_FIELD);
			property_info.value_length = tvb_get_letohs(tvb, tvb_offset   + 	PROPERTY_DECLARATION_VALUE_LENGTH_FIELD);
			property_info.name = tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_offset + PROPERTY_DECLARATION_HEADER_LENGTH, property_name_length, ENC_ASCII);
			property_info.name_length = property_name_length;
			property_info.tvb_offset = tvb_offset;
			property_info.tvb_property_length = PROPERTY_DECLARATION_HEADER_LENGTH + property_name_length + property_info.value_length;
			if(!PINFO_FD_VISITED(pinfo)){
				property_summary_map_insert(property_map, property_info.id, &property_info);
			}
			tvb_offset += PROPERTY_DECLARATION_HEADER_LENGTH + property_name_length;
			break;
		case PROPERTY_UPDATE_PAYLOAD:
			property_info.id  = tvb_get_guint8(tvb, tvb_offset   + 	PROPERTY_UPDATE_ID_FIELD);
			property_info.value_length = tvb_get_letohs(tvb, tvb_offset   + 	PROPERTY_UPDATE_VALUE_LENGTH_FIELD);
			property_info.tvb_offset = tvb_offset;
			property_info.tvb_property_length = PROPERTY_UPDATE_HEADER_LENGTH + property_info.value_length;
			property_summary = property_map_lookup(property_map, property_info.id);
			if(property_summary != NULL){
				property_info.prefix = property_summary->prefix;
				property_info.unit = property_summary->unit;
				property_info.type = property_summary->type;
				property_info.name = property_summary->name;
			}else{
				printf("[error] unknown property ID: %d\n", property_info.id);
				property_info.prefix = PREFIX_NONE;
				property_info.unit = UNIT_NONE;
				property_info.type = TYPE_INVALID;
				property_info.name =  wmem_strdup_printf(wmem_packet_scope(), PROPERTY_UNKNOWN_NAME);
			}
			tvb_offset += PROPERTY_UPDATE_HEADER_LENGTH;
			break;
		}
		switch(property_info.type){
		case 	TYPE_BOOLEAN:
			property_info.value.boolean_v = tvb_get_guint8(tvb, tvb_offset);
			break;
		case	TYPE_INT8:
			property_info.value.int8_v = (gint8)tvb_get_guint8(tvb, tvb_offset);
			break;
		case	TYPE_INT16:
			property_info.value.int16_v = (gint16)tvb_get_letohs(tvb, tvb_offset);
			break;
		case	TYPE_INT32:
			property_info.value.int32_v = (gint32)tvb_get_letohl(tvb, tvb_offset);
			break;
		case	TYPE_INT64:
			property_info.value.int64_v = (gint64)tvb_get_letoh64(tvb, tvb_offset);
			break;
		case	TYPE_UINT8:
			property_info.value.uint8_v = tvb_get_guint8(tvb, tvb_offset);
			break;
		case	TYPE_UINT16:
			property_info.value.uint16_v = tvb_get_letohs(tvb, tvb_offset);
			break;
		case	TYPE_UINT32:
			property_info.value.uint32_v = tvb_get_letohl(tvb, tvb_offset);
			break;
		case	TYPE_UINT64:
			property_info.value.uint64_v = tvb_get_letoh64(tvb, tvb_offset);
			break;
		case	TYPE_FLOAT:
			property_info.value.float_v = tvb_get_letohieee_float(tvb, tvb_offset);
			break;
		case	TYPE_DOUBLE:
			property_info.value.double_v = tvb_get_letohieee_double(tvb, tvb_offset);
			break;
		case	TYPE_ASCII_ARRAY:
			property_info.value.char_array_v = tvb_get_string_enc(wmem_packet_scope(), tvb, tvb_offset, property_info.value_length, ENC_ASCII);
			break;
		case	TYPE_BYTE_ARRAY:
			property_info.value.byte_array_v = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, tvb_offset, property_info.value_length);
			break;
		default:
			property_info.type =  TYPE_INVALID;
			break;
		}
		wmem_array_append(result->properties_list, &property_info, 1);
		properties_count --;
		tvb_offset += property_info.value_length;

	}
	result->tvb_offset = tvb_offset;
	return result;
}

gchar*
property_to_INFO_str(property_info_s* property_info){
	gchar* property_str;
	switch(property_info->type){
	case 	TYPE_BOOLEAN:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %s%s%s",
						property_info->name,
						val_to_str(property_info->value.boolean_v, value_names_dictionary, "[unknown value code (%"PRIu8")]"),
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_INT8:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRId8"%s%s",
						property_info->name,
						property_info->value.int8_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_INT16:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRId16"%s%s",
						property_info->name,
						property_info->value.int16_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_INT32:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRId32"%s%s",
						property_info->name,
						property_info->value.int32_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_INT64:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"G_GINT64_FORMAT"%s%s",
						property_info->name,
						property_info->value.int64_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,	"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_UINT8:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRIu8"%s%s",
						property_info->name,
						property_info->value.uint8_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_UINT16:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRIu16"%s%s",
						property_info->name,
						property_info->value.uint16_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_UINT32:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"PRIu32"%s%s",
						property_info->name,
						property_info->value.uint32_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_UINT64:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %"G_GUINT64_FORMAT"%s%s",
						property_info->name,
						property_info->value.uint64_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_FLOAT:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %f%s%s",
						property_info->name,
						property_info->value.float_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_DOUBLE:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %lf%s%s",
						property_info->name,
						property_info->value.double_v,
						val_to_str(property_info->prefix, prefix_names_dictionary,"[unknown prefix code (%"PRIu16")]"),
						val_to_str(property_info->unit, unit_names_dictionary,"[unknown unit code (%"PRIu16")]")
				);
		break;
	case	TYPE_ASCII_ARRAY:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %s",
						property_info->name,
						property_info->value.char_array_v
				);
		break;
	case	TYPE_BYTE_ARRAY:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: %s",
						property_info->name,
						bytestring_to_str(wmem_packet_scope(), property_info->value.byte_array_v, property_info->value_length, '\0')
				);
		break;
	default:
		property_str =
				wmem_strdup_printf(wmem_packet_scope(),
						"%s: [invalid type, cannot display]",
						property_info->name
				);
		break;
	}
	return property_str;
}

void
display_property_value(property_info_s* property_info, tvbuff_t* tvb, proto_tree* tree){
	switch(property_info->type){
	case 	TYPE_BOOLEAN:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueboolean, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_INT8:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueint8, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_INT16:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueint16, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_INT32:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueint32, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_INT64:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueint64, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_UINT8:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueuint8, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_UINT16:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueuint16, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_UINT32:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueuint32, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_UINT64:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueuint64, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_FLOAT:
		proto_tree_add_item(tree, hf_sensorlab_propertyvaluefloat, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_DOUBLE:
		proto_tree_add_item(tree, hf_sensorlab_propertyvaluedouble, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_LITTLE_ENDIAN);
		break;
	case	TYPE_ASCII_ARRAY:
		proto_tree_add_item(tree, hf_sensorlab_propertyvalueasciiarray, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_NA);
		break;
	case	TYPE_BYTE_ARRAY:
		proto_tree_add_item(tree, hf_sensorlab_propertyvaluebytearray, tvb, property_info->tvb_offset + property_info->tvb_property_length - property_info->value_length, property_info->value_length, ENC_NA);
		break;
	default:
		/*TODO: expert field for error*/
		break;
	}
}
void
display_property_declaration(property_info_s* property_info, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree_add_item(tree, hf_sensorlab_propertyid, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_ID_FIELD, PROPERTY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertyprefix, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_UNIT_PREFIX_FIELD, PROPERTY_UNIT_PREFIX_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertyunit, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_UNIT_FIELD, PROPERTY_UNIT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertytype, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_TYPE_FIELD, PROPERTY_TYPE_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertynamelength, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_NAME_LENGTH_FIELD, NAME_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertyvaluelength, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_VALUE_LENGTH_FIELD, PROPERTY_VALUE_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertyname, tvb, property_info->tvb_offset + PROPERTY_DECLARATION_HEADER_LENGTH, property_info->name_length, ENC_ASCII);
	display_property_value(property_info, tvb, tree );
}

void
display_property_update(property_info_s* property_info, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree_add_item(tree, hf_sensorlab_propertyid, tvb, property_info->tvb_offset + PROPERTY_UPDATE_ID_FIELD, PROPERTY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_sensorlab_propertyvaluelength, tvb, property_info-> tvb_offset + PROPERTY_UPDATE_VALUE_LENGTH_FIELD, PROPERTY_VALUE_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	display_property_value(property_info, tvb,  tree);
}

void
display_node_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"] " , info->node_id);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, NODE_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_node_remove(packet_info* pinfo, sensorlab_frame_info_s* info, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"] " , info->node_id);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
}

void
display_node_property_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"] " , info->node_id);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, NODE_PROPERTY_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_node_property_update(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"] " , info->node_id);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, NODE_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_update(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_entity_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, ENTITY_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entitynamelength, tvb, ENTITY_ADD_NAME_LENGTH_FIELD, NAME_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = 	proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, ENTITY_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityname, tvb, ENTITY_ADD_NAME_FIELD, (int)strlen(info->payload.entity_info.name), ENC_NA);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_entity_remove(packet_info* pinfo, sensorlab_frame_info_s* info, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, ENTITY_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entitynamelength, tvb, ENTITY_ADD_NAME_LENGTH_FIELD, NAME_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
}

void
display_entity_property_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, ENTITY_PROPERTY_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, ENTITY_PROPERTY_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_entity_property_update(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_item* properties_count_item = NULL;
	proto_tree* properties_tree = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, ENTITY_PROPERTY_UPDATE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, ENTITY_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_update(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_link_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* source_properties, properties_and_offset_s* target_properties, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* source_properties_tree = NULL;
	proto_tree* target_properties_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* source_properties_count_item = NULL;
	proto_item* target_properties_count_item = NULL;
	proto_item* properties_count_item = NULL;
	property_info_s* property_info;
	guint source_properties_count;
	guint target_properties_count;
	guint properties_count;
	guint16 index;


	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, LINK_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_linkid, tvb, LINK_ADD_ID_FIELD, LINK_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	source_properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_sourcepropertiescount, tvb, LINK_ADD_SOURCE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	target_properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_targetpropertiescount, tvb, LINK_ADD_TARGET_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, LINK_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	source_properties_tree = proto_item_add_subtree(source_properties_count_item, ett_source_properties);
	target_properties_tree = proto_item_add_subtree(target_properties_count_item, ett_target_properties);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	source_properties_count = wmem_array_get_count(source_properties->properties_list);
	target_properties_count = wmem_array_get_count(target_properties->properties_list);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(source_properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "source: ");
		for(index = 0; index<source_properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(source_properties->properties_list, index);
			display_property_update(property_info, tvb,  source_properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
	if(target_properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "target: ");
		for(index = 0; index<target_properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(target_properties->properties_list, index);
			display_property_update(property_info, tvb,  target_properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_link_remove(packet_info* pinfo, sensorlab_frame_info_s* info, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, LINK_REMOVE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_linkid, tvb, LINK_REMOVE_ID_FIELD, PROPERTY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
}

void
display_link_property_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* properties_count_item = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, LINK_PROPERTY_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_linkid, tvb, LINK_PROPERTY_ADD_ID_FIELD, LINK_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, LINK_PROPERTY_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_link_property_update(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* properties_count_item = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, LINK_PROPERTY_UPDATE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_linkid, tvb, LINK_PROPERTY_UPDATE_ID_FIELD, PROPERTY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, LINK_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_update(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_frame_produce(packet_info* pinfo, sensorlab_frame_info_s* info, gchar* frame_dissector_name, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* frame_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* frame_item = NULL;
	proto_item* properties_count_item = NULL;
	dissector_handle_t frame_dissector;
	tvbuff_t* payload_tvb;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_PRODUCE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_PRODUCE_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedatalength, tvb, FRAME_PRODUCE_DATA_LENGTH_FIELD, FRAME_DATA_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item  = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, FRAME_PRODUCE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	frame_item =  proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedata, tvb, FRAME_PRODUCE_DATA_FIELD, info->payload.frame_info.data_length, ENC_NA);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);

	frame_dissector =find_dissector(frame_dissector_name);
	if(frame_dissector && info->payload.frame_info.data_length >0){
		payload_tvb = tvb_new_subset(tvb, FRAME_PRODUCE_DATA_FIELD,  info->payload.frame_info.data_length, -1);
		frame_tree = proto_item_add_subtree(frame_item, ett_frame);
		call_dissector(frame_dissector, payload_tvb, pinfo, frame_tree);
	}

	col_clear(pinfo->cinfo,COL_INFO);
	if(info->payload.frame_info.data_length >0){
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: %s ", info->node_id, info->payload.entity_info.name, bytestring_to_str(wmem_packet_scope(), info->payload.frame_info.data,info->payload.frame_info.data_length,':'));
	}else{
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: <no data>", info->node_id, info->payload.entity_info.name);
	}
	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_frame_data_update(packet_info* pinfo, sensorlab_frame_info_s* info, gchar* frame_dissector_name,  tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* frame_tree = NULL;
	proto_item* frame_item = NULL;
	dissector_handle_t frame_dissector;
	tvbuff_t* payload_tvb;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_DATA_UPDATE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_DATA_UPDATE_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedatalength, tvb, FRAME_DATA_UPDATE_DATA_LENGTH_FIELD, FRAME_DATA_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	frame_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedata, tvb, FRAME_DATA_UPDATE_DATA_FIELD, info->payload.frame_info.data_length, ENC_NA);

	frame_dissector =find_dissector(frame_dissector_name);
	if(frame_dissector && info->payload.frame_info.data_length >0){
		payload_tvb = tvb_new_subset(tvb, FRAME_DATA_UPDATE_DATA_FIELD,  info->payload.frame_info.data_length, -1);
		frame_tree = proto_item_add_subtree(frame_item, ett_frame);
		call_dissector(frame_dissector, payload_tvb, pinfo, frame_tree);
	}

	col_clear(pinfo->cinfo,COL_INFO);
	if(info->payload.frame_info.data_length >0){
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: %s ", info->node_id, info->payload.entity_info.name, bytestring_to_str(wmem_packet_scope(), info->payload.frame_info.data,info->payload.frame_info.data_length,':'));
	}else{
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: <no data>", info->node_id, info->payload.entity_info.name);
	}
}

void
display_frame_property_add(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* properties_count_item = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_PROPERTY_ADD_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_PROPERTY_ADD_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, FRAME_PROPERTY_ADD_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_frame_property_update(packet_info* pinfo, sensorlab_frame_info_s* info, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* properties_count_item = NULL;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_PROPERTY_UPDATE_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_PROPERTY_UPDATE_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, FRAME_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);

	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) " , info->node_id, info->payload.entity_info.name);

	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "link: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_update(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_frame_tx(packet_info* pinfo, sensorlab_frame_info_s* info, gchar* frame_dissector_name,  tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* frame_tree = NULL;

	proto_item* frame_item = NULL;

	dissector_handle_t frame_dissector;
	tvbuff_t* payload_tvb;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_TX_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_TX_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedatalength, tvb, FRAME_TX_DATA_LENGTH_FIELD, FRAME_DATA_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	frame_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedata, tvb, FRAME_TX_DATA_FIELD, info->payload.frame_info.data_length, ENC_NA);

	frame_dissector =find_dissector(frame_dissector_name);
	if(frame_dissector && info->payload.frame_info.data_length >0){
		payload_tvb = tvb_new_subset(tvb, FRAME_TX_DATA_FIELD,  info->payload.frame_info.data_length, -1);
		frame_tree = proto_item_add_subtree(frame_item, ett_frame);
		call_dissector(frame_dissector, payload_tvb, pinfo, frame_tree);
	}

	col_clear(pinfo->cinfo,COL_INFO);
	if(info->payload.frame_info.data_length >0){
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: %s ", info->node_id, info->payload.entity_info.name, bytestring_to_str(wmem_packet_scope(), info->payload.frame_info.data,info->payload.frame_info.data_length,':'));
	}else{
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: <no data>", info->node_id, info->payload.entity_info.name);
	}
}

void
display_frame_rx(packet_info* pinfo, sensorlab_frame_info_s* info, gchar* frame_dissector_name, properties_and_offset_s* properties, tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* frame_tree = NULL;
	proto_tree* properties_tree = NULL;
	proto_item* frame_item = NULL;
	proto_item* properties_count_item = NULL;
	dissector_handle_t frame_dissector;
	tvbuff_t* payload_tvb;
	property_info_s* property_info;
	guint properties_count;
	guint16 index;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_RX_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_RX_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedatalength, tvb, FRAME_RX_DATA_LENGTH_FIELD, FRAME_DATA_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	properties_count_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_propertiescount, tvb, FRAME_RX_PROPERTIES_COUNT_FIELD, PROPERTIES_COUNT_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	frame_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedata, tvb, FRAME_RX_DATA_FIELD, info->payload.frame_info.data_length, ENC_NA);
	properties_tree = proto_item_add_subtree(properties_count_item, ett_properties);

	frame_dissector =find_dissector(frame_dissector_name);
	if(frame_dissector && info->payload.frame_info.data_length >0){
		payload_tvb = tvb_new_subset(tvb, FRAME_RX_DATA_FIELD,  info->payload.frame_info.data_length, -1);
		frame_tree = proto_item_add_subtree(frame_item, ett_frame);
		call_dissector(frame_dissector, payload_tvb, pinfo, frame_tree);
	}
	col_clear(pinfo->cinfo,COL_INFO);
	if(info->payload.frame_info.data_length >0){
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: %s ", info->node_id, info->payload.entity_info.name, bytestring_to_str(wmem_packet_scope(), info->payload.frame_info.data,info->payload.frame_info.data_length,':'));
	}else{
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: <no data>", info->node_id, info->payload.entity_info.name);
	}

	properties_count = wmem_array_get_count(properties->properties_list);
	if(properties_count > 0){
		col_append_fstr(pinfo->cinfo, COL_INFO, "frame: ");
		for(index = 0; index<properties_count; index++){
			property_info = (property_info_s *)wmem_array_index(properties->properties_list, index);
			display_property_declaration(property_info, tvb,  properties_tree);
			col_append_fstr(pinfo->cinfo, COL_INFO, "<%s> ", property_to_INFO_str(property_info));
		}
	}
}

void
display_frame_consume(packet_info* pinfo, sensorlab_frame_info_s* info, gchar* frame_dissector_name,  tvbuff_t* tvb,  proto_tree* tree){
	proto_tree* sensorlab_tree = NULL;
	proto_tree* frame_tree = NULL;

	proto_item* frame_item = NULL;

	dissector_handle_t frame_dissector;
	tvbuff_t* payload_tvb;

	sensorlab_tree = proto_item_add_subtree(tree, ett_sensorlab);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_nodeid, tvb, NODE_ID_FIELD, NODE_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_eventid, tvb, EVENT_ID_FIELD, EVENT_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_entityid, tvb, FRAME_CONSUME_ENTITY_ID_FIELD, ENTITY_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_frameid, tvb, FRAME_CONSUME_ID_FIELD, FRAME_ID_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedatalength, tvb, FRAME_CONSUME_DATA_LENGTH_FIELD, FRAME_DATA_LENGTH_FIELD_LENGTH, ENC_LITTLE_ENDIAN);
	frame_item = proto_tree_add_item(sensorlab_tree, hf_sensorlab_framedata, tvb, FRAME_CONSUME_DATA_FIELD, info->payload.frame_info.data_length, ENC_NA);
	frame_tree = proto_item_add_subtree(frame_item, ett_properties);

	frame_dissector =find_dissector(frame_dissector_name);
	if(frame_dissector && info->payload.frame_info.data_length >0){
		payload_tvb = tvb_new_subset(tvb, FRAME_CONSUME_DATA_FIELD,  info->payload.frame_info.data_length, -1);
		frame_tree = proto_item_add_subtree(frame_item, ett_frame);
		call_dissector(frame_dissector, payload_tvb, pinfo, frame_tree);
	}

	col_clear(pinfo->cinfo,COL_INFO);
	if(info->payload.frame_info.data_length >0){
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: %s ", info->node_id, info->payload.entity_info.name, bytestring_to_str(wmem_packet_scope(), info->payload.frame_info.data,info->payload.frame_info.data_length,':'));
	}else{
		col_add_fstr(pinfo->cinfo, COL_INFO, "[Node %"PRIu32"](%s) :: <no data>", info->node_id, info->payload.entity_info.name);
	}
}

void
register_frame_dissector_if_any(entity_scope_s* entity_scope, wmem_array_t* properties){
	guint properties_count;
	property_info_s* property_info;
	guint16 index;

	properties_count = wmem_array_get_count(properties);
	for(index = 0; index<properties_count; index++){
		property_info = (property_info_s *)wmem_array_index(properties, index);
		if(!strcmp(property_info->name, PROPERTY_NAME_FRAME_DISSECTOR)){
			wmem_free(wmem_file_scope(),entity_scope->frame_dissector_name);
			entity_scope->frame_dissector_name = wmem_strdup_printf(wmem_file_scope(), "%s", property_info->value.char_array_v);
			break;
		}
	}
}

static int
dissect_sensorlab(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_){
	sensorlab_frame_info_s* info;
	node_scope_s* node_scope;
	entity_scope_s* entity_scope;
	link_scope_s* link_scope;
	frame_scope_s* frame_scope;
	properties_and_offset_s* source_properties_and_offset;
	properties_and_offset_s* target_properties_and_offset;
	properties_and_offset_s* properties_and_offset;
	guint8 properties_count;
	guint8 source_properties_count;
	guint8 target_properties_count;
	guint8 entity_name_length;
	guint32 tvb_offset;
	gchar* frame_dissector_name;

	info = (sensorlab_frame_info_s*)wmem_alloc(wmem_packet_scope(), sizeof(sensorlab_frame_info_s));

	info->date = pinfo->fd->abs_ts;
	info->node_id = tvb_get_letohl(tvb, 	NODE_ID_FIELD);
	info->event_id = tvb_get_guint8(tvb,  	EVENT_ID_FIELD);

	tvb_offset = 0;

	switch(info->event_id){
	case EVENT_NODE_ADD:
		if(!PINFO_FD_VISITED(pinfo)){
			node_scope = node_scope_map_insert(info->node_id);
		} else {
			node_scope = node_scope_map_lookup(info->node_id);
		}
		properties_count = tvb_get_guint8(tvb, NODE_ADD_PROPERTIES_COUNT_FIELD);
		properties_and_offset = dissect_property_payloads(PROPERTY_DECLARATION_PAYLOAD,tvb, pinfo, NODE_ADD_PROPERTIES,properties_count,node_scope->property_map);
		info->payload.node_info.properties = properties_and_offset->properties_list;
		tvb_offset = properties_and_offset->tvb_offset;
		if(tree){
			display_node_add(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_NODE_PROPERTY_ADD:
		node_scope = node_scope_map_lookup(info->node_id);
		properties_count = tvb_get_guint8(tvb, NODE_PROPERTY_ADD_PROPERTIES_COUNT_FIELD);
		if(node_scope != NULL){
			properties_and_offset = dissect_property_payloads(PROPERTY_DECLARATION_PAYLOAD,tvb, pinfo, NODE_PROPERTY_ADD_PROPERTIES,properties_count,node_scope->property_map);
			info->payload.node_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
			if(tree){
				display_node_property_add(pinfo, info, properties_and_offset, tvb, tree);
			}
		}
		break;
	case EVENT_NODE_PROPERTY_UPDATE:
		node_scope = node_scope_map_lookup(info->node_id);
		properties_count = tvb_get_guint8(tvb, NODE_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD);
		if(node_scope != NULL){
			properties_and_offset =  dissect_property_payloads(PROPERTY_UPDATE_PAYLOAD,tvb, pinfo, NODE_PROPERTY_UPDATE_PROPERTIES,properties_count,node_scope->property_map);
			info->payload.node_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
			if(tree){
				display_node_property_update(pinfo, info, properties_and_offset, tvb, tree);
			}
		}
		break;
	case EVENT_NODE_REMOVE:
		info->payload.node_info.properties = NULL;
		if(tree){
			display_node_remove(pinfo, info, tvb, tree);
		}
		break;
	case EVENT_ENTITY_ADD:
		info->payload.entity_info.id = tvb_get_guint8(tvb, 	ENTITY_ADD_ENTITY_ID_FIELD);
		entity_name_length = tvb_get_guint8(tvb, ENTITY_ADD_NAME_LENGTH_FIELD);
		properties_count = tvb_get_guint8(tvb,ENTITY_ADD_PROPERTIES_COUNT_FIELD);
		info->payload.entity_info.name = tvb_get_string_enc(wmem_packet_scope(), tvb, ENTITY_ADD_NAME_FIELD, entity_name_length, ENC_ASCII);
		node_scope = node_scope_map_lookup(info->node_id);
		if(!PINFO_FD_VISITED(pinfo)){
			entity_scope = entity_scope_map_insert(node_scope,info->payload.entity_info.id,info->payload.entity_info.name);
		}else{
			entity_scope = entity_scope_map_lookup(node_scope, info->payload.entity_info.id);
		}
		if(entity_scope){
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					ENTITY_ADD_NAME_FIELD + entity_name_length,
					properties_count,
					entity_scope->property_map );
			info->payload.entity_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;

			register_frame_dissector_if_any(entity_scope, properties_and_offset->properties_list);

		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_entity_add(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_ENTITY_PROPERTY_ADD:
		info->payload.entity_info.id = tvb_get_guint8(tvb, 	ENTITY_PROPERTY_ADD_ENTITY_ID_FIELD);
		properties_count = tvb_get_guint8(tvb,ENTITY_PROPERTY_ADD_PROPERTIES_COUNT_FIELD);
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.entity_info.id);
		if(entity_scope){
			info->payload.entity_info.name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					ENTITY_PROPERTY_ADD_PROPERTIES,
					properties_count,
					entity_scope->property_map );
			info->payload.entity_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
			printf("[error] entity scope for entity ID (%d) not found for node %d!\n",info->payload.entity_info.id, info->node_id);
		}
		if(tree){
			display_entity_property_add(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_ENTITY_PROPERTY_UPDATE:
		info->payload.entity_info.id = tvb_get_guint8(tvb, 	ENTITY_PROPERTY_UPDATE_ENTITY_ID_FIELD);
		properties_count = tvb_get_guint8(tvb, ENTITY_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD);
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.entity_info.id);
		if(entity_scope){
			info->payload.entity_info.name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_UPDATE_PAYLOAD,
					tvb, pinfo,
					ENTITY_PROPERTY_UPDATE_PROPERTIES,
					properties_count,
					entity_scope->property_map );
			info->payload.entity_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
			printf("[error] entity scope for entity ID (%d) not found for node %d!\n",info->payload.entity_info.id, info->node_id);
		}
		if(tree){
			display_entity_property_update(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_ENTITY_REMOVE:
		info->payload.entity_info.id = tvb_get_guint8(tvb, 	ENTITY_REMOVE_ENTITY_ID_FIELD);
		info->payload.entity_info.properties = NULL;
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.entity_info.id);
		if(entity_scope){
			info->payload.entity_info.name = entity_scope->name;
		}else{
			printf("[error] entity scope for entity ID (%d) not found for node %d!\n",info->payload.entity_info.id, info->node_id);
		}
		break;
	case EVENT_LINK_ADD:
		info->payload.link_info.entity_id = tvb_get_guint8(tvb, LINK_ADD_ENTITY_ID_FIELD);
		info->payload.link_info.id 	= tvb_get_guint8(tvb, LINK_ADD_ID_FIELD);
		source_properties_count 	= tvb_get_guint8(tvb, LINK_ADD_SOURCE_PROPERTIES_COUNT_FIELD);
		target_properties_count 	= tvb_get_guint8(tvb, LINK_ADD_TARGET_PROPERTIES_COUNT_FIELD);
		properties_count       		= tvb_get_guint8(tvb, LINK_ADD_PROPERTIES_COUNT_FIELD);
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.link_info.entity_id);
		if(!PINFO_FD_VISITED(pinfo)){
			link_scope = link_scope_map_insert(entity_scope,info->payload.link_info.id);
		} else {
			link_scope = link_scope_map_lookup(entity_scope, info->payload.link_info.id);
		}
		if(link_scope){
			info->payload.link_info.entity_name = entity_scope->name;

			source_properties_and_offset = dissect_property_payloads( PROPERTY_UPDATE_PAYLOAD,
					tvb, pinfo,
					LINK_ADD_SOURCE_PROPERTIES,
					source_properties_count,
					entity_scope->property_map );

			info->payload.link_info.source_properties = source_properties_and_offset->properties_list;

			tvb_offset = source_properties_and_offset->tvb_offset;
			target_properties_and_offset = dissect_property_payloads( PROPERTY_UPDATE_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					target_properties_count,
					entity_scope->property_map );
			info->payload.link_info.target_properties = target_properties_and_offset->properties_list;
			tvb_offset = target_properties_and_offset->tvb_offset;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					properties_count,
					link_scope->property_map );
			info->payload.link_info.properties = properties_and_offset->properties_list;
			tvb_offset = target_properties_and_offset->tvb_offset;
		}else{
			source_properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			source_properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
			target_properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			target_properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_link_add(pinfo, info, source_properties_and_offset, target_properties_and_offset, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_LINK_PROPERTY_ADD:
		info->payload.link_info.entity_id = tvb_get_guint8(tvb, LINK_PROPERTY_ADD_ENTITY_ID_FIELD);
		info->payload.link_info.id 	= tvb_get_guint8(tvb, LINK_PROPERTY_ADD_ID_FIELD);
		properties_count        	= tvb_get_guint8(tvb, LINK_PROPERTY_ADD_PROPERTIES_COUNT_FIELD);

		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.link_info.entity_id);
		link_scope = link_scope_map_lookup(entity_scope, info->payload.link_info.id);

		if(link_scope){
			info->payload.link_info.entity_name = entity_scope->name;
			info->payload.link_info.source_properties = NULL;
			info->payload.link_info.target_properties = NULL;

			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					LINK_PROPERTY_ADD_PROPERTIES,
					properties_count,
					link_scope->property_map );
			info->payload.link_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_link_property_add(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_LINK_PROPERTY_UPDATE:
		info->payload.link_info.entity_id = tvb_get_guint8(tvb, LINK_PROPERTY_UPDATE_ENTITY_ID_FIELD);
		info->payload.link_info.id 	= tvb_get_guint8(tvb, LINK_PROPERTY_UPDATE_ID_FIELD);
		properties_count        	= tvb_get_guint8(tvb, LINK_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD);

		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.link_info.entity_id);
		link_scope = link_scope_map_lookup(entity_scope, info->payload.link_info.id);

		if(link_scope){
			info->payload.link_info.entity_name = entity_scope->name;
			info->payload.link_info.source_properties = NULL;
			info->payload.link_info.target_properties = NULL;
			properties_and_offset = dissect_property_payloads( PROPERTY_UPDATE_PAYLOAD,
					tvb, pinfo,
					LINK_PROPERTY_UPDATE_PROPERTIES,
					properties_count,
					link_scope->property_map );
			info->payload.link_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_link_property_update(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_LINK_REMOVE:
		info->payload.link_info.entity_id = tvb_get_guint8(tvb, LINK_REMOVE_ENTITY_ID_FIELD);
		info->payload.link_info.id 	= tvb_get_guint8(tvb, LINK_REMOVE_ID_FIELD);

		info->payload.link_info.properties = NULL;
		info->payload.link_info.source_properties = NULL;
		info->payload.link_info.target_properties = NULL;
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.link_info.entity_id);
		link_scope = link_scope_map_lookup(entity_scope, info->payload.link_info.id);
		if(link_scope){
			info->payload.link_info.entity_name = entity_scope->name;
		}
		if(tree){
			display_link_remove(pinfo, info, tvb, tree);
		}
		break;

	case EVENT_FRAME_PRODUCE:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_PRODUCE_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_PRODUCE_ID_FIELD);
		info->payload.frame_info.data_length	= tvb_get_letohs(tvb, FRAME_PRODUCE_DATA_LENGTH_FIELD);
		properties_count 						= tvb_get_guint8(tvb, FRAME_PRODUCE_PROPERTIES_COUNT_FIELD);
		info->payload.frame_info.data 			= (gchar*)tvb_memdup(wmem_packet_scope(), tvb, FRAME_PRODUCE_DATA_FIELD, info->payload.frame_info.data_length);

		tvb_offset = FRAME_PRODUCE_DATA_FIELD + info->payload.frame_info.data_length;

		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		if(!PINFO_FD_VISITED(pinfo)){
			frame_scope = frame_scope_map_insert(node_scope, info->payload.frame_info.id);
		}else{
			frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);
		}

		if(frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					properties_count,
					frame_scope->property_map );
			info->payload.frame_info.properties = properties_and_offset->properties_list;
			frame_dissector_name = entity_scope->frame_dissector_name;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			frame_dissector_name = wmem_strdup_printf(wmem_packet_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_frame_produce(pinfo, info,  frame_dissector_name, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_FRAME_DATA_UPDATE:
		info->payload.frame_info.entity_id = tvb_get_guint8(tvb, FRAME_DATA_UPDATE_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_DATA_UPDATE_ID_FIELD);
		info->payload.frame_info.data_length	= tvb_get_letohs(tvb, FRAME_DATA_UPDATE_DATA_LENGTH_FIELD);
		tvb_offset = FRAME_DATA_UPDATE_DATA_FIELD;
		info->payload.frame_info.data 			= (gchar*)tvb_memdup(wmem_packet_scope(), tvb, tvb_offset, info->payload.frame_info.data_length);
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);

		if(frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			frame_dissector_name = entity_scope->frame_dissector_name;
		}else{
			frame_dissector_name = wmem_strdup_printf(wmem_packet_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
		}
		if(tree){
			display_frame_data_update(pinfo, info, frame_dissector_name, tvb, tree);
		}
		break;
	case EVENT_FRAME_PROPERTY_ADD:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_PROPERTY_ADD_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_PROPERTY_ADD_ID_FIELD);
		properties_count 						= tvb_get_guint8(tvb, FRAME_PROPERTY_ADD_PROPERTIES_COUNT_FIELD);
		tvb_offset = FRAME_PROPERTY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH;
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);

		if(frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					properties_count,
					frame_scope->property_map );
			info->payload.frame_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_frame_property_add(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_FRAME_PROPERTY_UPDATE:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_PROPERTY_UPDATE_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_PROPERTY_UPDATE_ID_FIELD);
		properties_count 						= tvb_get_guint8(tvb, FRAME_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD);
		tvb_offset = FRAME_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH;
		node_scope = node_scope_map_lookup(info->node_id);
		frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);

		if(frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					properties_count,
					frame_scope->property_map );
			info->payload.frame_info.properties = properties_and_offset->properties_list;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_frame_property_update(pinfo, info, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_FRAME_TX:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_TX_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_TX_ID_FIELD);
		info->payload.frame_info.data_length	= tvb_get_letohs(tvb, FRAME_TX_DATA_LENGTH_FIELD);
		tvb_offset = FRAME_TX_DATA_FIELD;
		info->payload.frame_info.data 			= (gchar*)tvb_memdup(wmem_packet_scope(), tvb, tvb_offset, info->payload.frame_info.data_length);
		info->payload.frame_info.properties 	= NULL;
		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);

		if(entity_scope != NULL && frame_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			frame_dissector_name = entity_scope->frame_dissector_name;
		}else{
			frame_dissector_name = wmem_strdup_printf(wmem_packet_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
		}
		if(tree){
			display_frame_tx(pinfo, info, frame_dissector_name, tvb, tree);
		}
		break;
	case EVENT_FRAME_RX:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_RX_ENTITY_ID_FIELD);
		info->payload.frame_info.id 						= tvb_get_guint8(tvb, FRAME_RX_ID_FIELD);
		info->payload.frame_info.data_length	= tvb_get_letohs(tvb, FRAME_RX_DATA_LENGTH_FIELD);
		properties_count 										= tvb_get_guint8(tvb, FRAME_RX_PROPERTIES_COUNT_FIELD);
		info->payload.frame_info.data 				= (gchar*)tvb_memdup(wmem_packet_scope(), tvb, FRAME_RX_DATA_FIELD, info->payload.frame_info.data_length);

		tvb_offset = FRAME_RX_DATA_FIELD + info->payload.frame_info.data_length;

		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		if(!PINFO_FD_VISITED(pinfo)){
			frame_scope = frame_scope_map_insert(node_scope, info->payload.frame_info.id);
		} else {
			frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);
		}
		if(frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			properties_and_offset = dissect_property_payloads( PROPERTY_DECLARATION_PAYLOAD,
					tvb, pinfo,
					tvb_offset,
					properties_count,
					frame_scope->property_map );
			info->payload.frame_info.properties = properties_and_offset->properties_list;
			frame_dissector_name = entity_scope->frame_dissector_name;
			tvb_offset = properties_and_offset->tvb_offset;
		}else{
			frame_dissector_name = wmem_strdup_printf(wmem_packet_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
			properties_and_offset =(properties_and_offset_s*)wmem_alloc(wmem_packet_scope(), sizeof(properties_and_offset_s));
			properties_and_offset->properties_list = wmem_array_new(wmem_packet_scope(), sizeof(property_info_s));
		}
		if(tree){
			display_frame_rx(pinfo, info, frame_dissector_name, properties_and_offset, tvb, tree);
		}
		break;
	case EVENT_FRAME_CONSUME:
		info->payload.frame_info.entity_id 		= tvb_get_guint8(tvb, FRAME_CONSUME_ENTITY_ID_FIELD);
		info->payload.frame_info.id 			= tvb_get_guint8(tvb, FRAME_CONSUME_ID_FIELD);
		info->payload.frame_info.data_length	= tvb_get_letohs(tvb, FRAME_CONSUME_DATA_LENGTH_FIELD);
		tvb_offset 								= FRAME_CONSUME_DATA_FIELD;
		info->payload.frame_info.data 			= (gchar*)tvb_memdup(wmem_packet_scope(), tvb, tvb_offset, info->payload.frame_info.data_length);
		info->payload.frame_info.properties 	= NULL;

		node_scope = node_scope_map_lookup(info->node_id);
		entity_scope = entity_scope_map_lookup(node_scope, info->payload.frame_info.entity_id);
		frame_scope = frame_scope_map_lookup(node_scope, info->payload.frame_info.id);

		if( frame_scope != NULL && entity_scope != NULL){
			info->payload.frame_info.entity_name = entity_scope->name;
			frame_dissector_name = entity_scope->frame_dissector_name;
		}else{
			frame_dissector_name = wmem_strdup_printf(wmem_packet_scope(), PROPERTY_FRAME_DISSECTOR_UNDEFINED);
		}
		if(tree){
			display_frame_consume(pinfo, info, frame_dissector_name,  tvb, tree);
		}
		break;
	default:
		/*TODO: how do I declare that the event is not recognized? Expert field? To investigate */
		expert_add_info(pinfo, tree, &ei_sensorlab_event_id);
		break;
	}
	return tvb_offset;
}
