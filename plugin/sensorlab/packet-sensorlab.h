/*
 * packet-sensorlab.h
 *
 *		@version 1.0
 *  	@date Aug 22, 2014
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
 */

#ifndef PACKET_SENSORLAB_H_
#define PACKET_SENSORLAB_H_


#include <stdlib.h>
#include <glib.h>
#include <wsutil/nstime.h>

#define PROPERTY_DECLARATION_PAYLOAD (0)
#define PROPERTY_UPDATE_PAYLOAD     (1)

typedef union {
	gboolean 			boolean_v;
	gint8				int8_v;
	gint16				int16_v;
	gint32				int32_v;
	gint64				int64_v;
	guint8 				uint8_v;
	guint16 			uint16_v;
	guint32 			uint32_v;
	guint64				uint64_v;
	gfloat 				float_v;
	gdouble 			double_v;
	gchar* 				char_array_v;
	const gchar*	 	byte_array_v;
} property_value_u;

typedef struct {
	guint8 				id;
	guint8	 			prefix;
	guint8 				unit;
	guint8	 			type;
	gchar* 				name;
	guint8				name_length;
	property_value_u 	value;
	guint16				value_length;
	gint32				tvb_offset;
	gint32				tvb_property_length;
} property_info_s;

typedef struct{
	guint8	 			id;
	guint8	 			prefix;
	guint8	 			unit;
	guint8	 			type;
	gchar* 				name;
}property_summary_s;

typedef struct {
	gint32				tvb_offset;
	wmem_array_t*		properties_list;
} properties_and_offset_s;


typedef struct{
	guint8	 					id;
	wmem_map_t* 		property_map;
} frame_scope_s;

typedef struct{
	guint8	 					id;
	wmem_map_t* 		property_map;
} link_scope_s;

typedef struct{
	guint8						id;
	gchar* 						name;
	gchar*						frame_dissector_name;
	wmem_map_t* 		property_map;
	wmem_map_t* 		link_scope_map;
}entity_scope_s;

typedef struct{
	guint32     		id;
	wmem_map_t* 		property_map;
	wmem_map_t* 		entity_scope_map;
	wmem_map_t* 		frame_scope_map;
}node_scope_s;


typedef struct {
	wmem_array_t*		properties;
} node_info_s;

typedef struct {
	guint8				id;
	gchar*				name;
	wmem_array_t*		properties;
} entity_info_s;

typedef struct {
	guint8				id;
	guint8				entity_id;
	gchar*				entity_name;
	wmem_array_t*		source_properties;
	wmem_array_t*		target_properties;
	wmem_array_t*		properties;
} link_info_s;

typedef struct {
	guint8  			id;
	guint8				entity_id;
	gchar*				entity_name;
	guint16				data_length;
	gchar* 				data;
	wmem_array_t*		properties;
} frame_info_s;

typedef union {
	node_info_s 		node_info;
	entity_info_s 		entity_info;
	link_info_s			link_info;
	frame_info_s		frame_info;
}payload_info_u;

typedef struct{
nstime_t				date;
	guint32				node_id;
	guint8				event_id;
	payload_info_u 		payload;
}sensorlab_frame_info_s;




#endif /* PACKET_SENSORLAB_H_ */
