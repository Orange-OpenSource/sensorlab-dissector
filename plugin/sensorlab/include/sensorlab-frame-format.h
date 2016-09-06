/*
 * sensorlab-frame-format.h
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
 *
 */

#ifndef PACKET_SENSORLABS_H_
#define SENSORLAB_FRAME_FORMAT

#define FIRST_BYTE 0
#define LAST_BYTE -1


/* fields lengths */
#define NODE_ID_FIELD_LENGTH 						   (4)
#define ENTITY_ID_FIELD_LENGTH						   (1)
#define EVENT_ID_FIELD_LENGTH						   (1)
#define PROPERTIES_COUNT_FIELD_LENGTH				   (1)
#define NAME_LENGTH_FIELD_LENGTH					   (1)
#define LINK_ID_FIELD_LENGTH						   (1)
#define FRAME_ID_FIELD_LENGTH						   (1)
#define FRAME_DATA_LENGTH_FIELD_LENGTH				   (2)
#define PROPERTY_ID_FIELD_LENGTH					   (1)
#define PROPERTY_UNIT_PREFIX_FIELD_LENGTH			   (1)
#define PROPERTY_UNIT_FIELD_LENGTH					   (1)
#define PROPERTY_TYPE_FIELD_LENGTH					   (1)
#define PROPERTY_VALUE_LENGTH_FIELD_LENGTH			   (2)

/* headers lengths */
#define SENSORLAB_HEADER_LENGTH					       (NODE_ID_FIELD_LENGTH + EVENT_ID_FIELD_LENGTH)
#define	NODE_HEADER_LENGTH							   (PROPERTIES_COUNT_FIELD_LENGTH)
#define	ENTITY_HEADER_LENGTH						   (ENTITY_ID_FIELD_LENGTH + PROPERTIES_COUNT_FIELD_LENGTH)
#define PROPERTY_DECLARATION_HEADER_LENGTH			   (PROPERTY_ID_FIELD_LENGTH + PROPERTY_UNIT_PREFIX_FIELD_LENGTH + \
													    PROPERTY_UNIT_FIELD_LENGTH + PROPERTY_TYPE_FIELD_LENGTH + \
													    NAME_LENGTH_FIELD_LENGTH + PROPERTY_VALUE_LENGTH_FIELD_LENGTH)
#define PROPERTY_UPDATE_HEADER_LENGTH				   (PROPERTY_ID_FIELD_LENGTH + PROPERTY_VALUE_LENGTH_FIELD_LENGTH)




#define SENSORLAB_HEADER							   (FIRST_BYTE)
/*
| `nodeID` | `eventID` |    `eventPayload`    |
|:--------:|:---------:|:--------------------:|
|  32bits  |   8bits   |    variable size     |
 */
#define NODE_ID_FIELD 								   (SENSORLAB_HEADER)
#define EVENT_ID_FIELD								   (NODE_ID_FIELD + NODE_ID_FIELD_LENGTH)
#define EVENT_PAYLOAD								   (EVENT_ID_FIELD + EVENT_ID_FIELD_LENGTH)


#define NODE_ADD_PAYLOAD							   (EVENT_PAYLOAD)
/*
| `propertiesCount` | `properties [...]` |
|:-----------------:|:------------------:|
|        8bits      |   variable size    |
*/
#define NODE_ADD_PROPERTIES_COUNT_FIELD					(NODE_ADD_PAYLOAD)
#define NODE_ADD_PROPERTIES								(NODE_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define NODE_PROPERTY_ADD_PAYLOAD						(EVENT_PAYLOAD)
/*
| `propertiesCount` | `properties [...]` |
|:-----------------:|:------------------:|
|        8bits      |   variable size    |
*/
#define NODE_PROPERTY_ADD_PROPERTIES_COUNT_FIELD		(NODE_PROPERTY_ADD_PAYLOAD)
#define NODE_PROPERTY_ADD_PROPERTIES					(NODE_PROPERTY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define NODE_PROPERTY_UPDATE_PAYLOAD					(EVENT_PAYLOAD)
/*
| `propertiesCount` | `properties [...]` |
|:-----------------:|:------------------:|
|        8bits      |   variable size    |
*/
#define NODE_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD		(NODE_PROPERTY_UPDATE_PAYLOAD)
#define NODE_PROPERTY_UPDATE_PROPERTIES					(NODE_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define NODE_REMOVE_PAYLOAD								(EVENT_PAYLOAD)
/*
-----
empty
-----
*/



#define ENTITY_ADD_PAYLOAD								(EVENT_PAYLOAD)
/*
| `entityID` | `entityNameLength` | `propertiesCount` |   `entityName`  | `properties [...]` |
|:----------:|:------------------:|:-----------------:|:---------------:|:------------------:|
|    8bits   |      8bits         |    8bits          | variable size   |  variable size     |
*/
#define ENTITY_ADD_ENTITY_ID_FIELD						(ENTITY_ADD_PAYLOAD)
#define ENTITY_ADD_NAME_LENGTH_FIELD					(ENTITY_ADD_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define ENTITY_ADD_PROPERTIES_COUNT_FIELD				(ENTITY_ADD_NAME_LENGTH_FIELD + NAME_LENGTH_FIELD_LENGTH)
#define ENTITY_ADD_NAME_FIELD							(ENTITY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define ENTITY_PROPERTY_ADD_PAYLOAD						(EVENT_PAYLOAD)
/*
| `entityID` | `propertiesCount` | `properties [...]` |
|:----------:|:-----------------:|:------------------:|
|    8bits   |        8bits      |   variable size    |
*/
#define ENTITY_PROPERTY_ADD_ENTITY_ID_FIELD				(ENTITY_PROPERTY_ADD_PAYLOAD)
#define ENTITY_PROPERTY_ADD_PROPERTIES_COUNT_FIELD		(ENTITY_PROPERTY_ADD_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define ENTITY_PROPERTY_ADD_PROPERTIES					(ENTITY_PROPERTY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define ENTITY_PROPERTY_UPDATE_PAYLOAD					(EVENT_PAYLOAD)
/*
| `entityID` | `propertiesCount` | `properties [...]` |
|:----------:|:-----------------:|:------------------:|
|    8bits   |        8bits      |   variable size    |
*/
#define ENTITY_PROPERTY_UPDATE_ENTITY_ID_FIELD			(ENTITY_PROPERTY_UPDATE_PAYLOAD)
#define ENTITY_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD	(ENTITY_PROPERTY_UPDATE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define ENTITY_PROPERTY_UPDATE_PROPERTIES				(ENTITY_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)


#define ENTITY_REMOVE_PAYLOAD							(EVENT_PAYLOAD)
/*
| `entityID` |
|:----------:|
|    8bits   |
*/
#define ENTITY_REMOVE_ENTITY_ID_FIELD					(ENTITY_REMOVE_PAYLOAD)


#define LINK_ADD_PAYLOAD								   	(EVENT_PAYLOAD)
/*
| `entityID` | `linkID` | `sourcePropertiesCount` | `targetPropertiesCount` | `linkPropertiesCount` | `sourceProperties [...]` | `targetProperties [...]` | `linkProperties [...]` |
|:----------:|:--------:|:-----------------------:|:-----------------------:|:---------------------:|:------------------------:|:------------------------:|:----------------------:|
|    8bits   |   8bits  |          8bits          |           8bits         |          8bits        |       variable size      |      variable size       |      variable size     |
*/
#define LINK_ADD_ENTITY_ID_FIELD						(LINK_ADD_PAYLOAD)
#define LINK_ADD_ID_FIELD								(LINK_ADD_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define LINK_ADD_SOURCE_PROPERTIES_COUNT_FIELD		   	(LINK_ADD_ID_FIELD + LINK_ID_FIELD_LENGTH)
#define LINK_ADD_TARGET_PROPERTIES_COUNT_FIELD		   	(LINK_ADD_SOURCE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)
#define LINK_ADD_PROPERTIES_COUNT_FIELD				   	(LINK_ADD_TARGET_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)
#define LINK_ADD_SOURCE_PROPERTIES						(LINK_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define LINK_PROPERTY_ADD_PAYLOAD						(EVENT_PAYLOAD)
/*
| `entityID` | `linkID` | `linkPropertiesCount` | `linkProperties [...]` |
|:----------:|:--------:|:---------------------:|:----------------------:|
|    8bits   |   8bits  |          8bits        |      variable size     |
*/
#define LINK_PROPERTY_ADD_ENTITY_ID_FIELD				(LINK_PROPERTY_ADD_PAYLOAD)
#define LINK_PROPERTY_ADD_ID_FIELD						(LINK_PROPERTY_ADD_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define LINK_PROPERTY_ADD_PROPERTIES_COUNT_FIELD		(LINK_PROPERTY_ADD_ID_FIELD + LINK_ID_FIELD_LENGTH)
#define LINK_PROPERTY_ADD_PROPERTIES					(LINK_PROPERTY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define LINK_PROPERTY_UPDATE_PAYLOAD					(EVENT_PAYLOAD)
/*
| `entityID` | `linkID` | `linkPropertiesCount` | `linkProperties [...]` |
|:----------:|:--------:|:---------------------:|:----------------------:|
|    8bits   |   8bits  |          8bits        |      variable size     |
*/
#define LINK_PROPERTY_UPDATE_ENTITY_ID_FIELD			(LINK_PROPERTY_UPDATE_PAYLOAD)
#define LINK_PROPERTY_UPDATE_ID_FIELD					(LINK_PROPERTY_UPDATE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define LINK_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD		(LINK_PROPERTY_UPDATE_ID_FIELD + LINK_ID_FIELD_LENGTH)
#define LINK_PROPERTY_UPDATE_PROPERTIES					(LINK_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define LINK_REMOVE_PAYLOAD								(EVENT_PAYLOAD)

/*
| `entityID` | `linkID` |
|:----------:|:--------:|
|    8bits   |   8bits  |
*/
#define LINK_REMOVE_ENTITY_ID_FIELD						(LINK_REMOVE_PAYLOAD)
#define LINK_REMOVE_ID_FIELD							(LINK_REMOVE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)

#define FRAME_PRODUCE_PAYLOAD							(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` |  `dataLength` | `propertiesCount` |     `data`      |  `frameProperties [...]` |
|:----------:|:---------:|:-------------:|:-----------------:|:---------------:|:------------------------:|
|    8bits   |   8bits   |    16bits     |        8bits      |  variable size  |      variable size       |
*/
#define FRAME_PRODUCE_ENTITY_ID_FIELD					(FRAME_PRODUCE_PAYLOAD)
#define FRAME_PRODUCE_ID_FIELD							(FRAME_PRODUCE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_PRODUCE_DATA_LENGTH_FIELD					(FRAME_PRODUCE_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_PRODUCE_PROPERTIES_COUNT_FIELD			(FRAME_PRODUCE_DATA_LENGTH_FIELD + FRAME_DATA_LENGTH_FIELD_LENGTH)
#define FRAME_PRODUCE_DATA_FIELD						(FRAME_PRODUCE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define FRAME_RX_PAYLOAD								(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` |  `dataLength` | `propertiesCount` |     `data`      |  `frameProperties [...]` |
|:----------:|:---------:|:-------------:|:-----------------:|:---------------:|:------------------------:|
|    8bits   |   8bits   |    16bits     |        8bits      |  variable size  |      variable size       |
*/
#define FRAME_RX_ENTITY_ID_FIELD						(FRAME_RX_PAYLOAD)
#define FRAME_RX_ID_FIELD								(FRAME_RX_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_RX_DATA_LENGTH_FIELD						(FRAME_RX_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_RX_PROPERTIES_COUNT_FIELD					(FRAME_RX_DATA_LENGTH_FIELD + FRAME_DATA_LENGTH_FIELD_LENGTH)
#define FRAME_RX_DATA_FIELD								(FRAME_RX_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define FRAME_PROPERTY_ADD_PAYLOAD						(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` | `propertiesCount` |  `frameProperties [...]` |
|:----------:|:---------:|:-----------------:|:------------------------:|
|    8bits   |   8bits   |        8bits      |      variable size       |
*/
#define FRAME_PROPERTY_ADD_ENTITY_ID_FIELD				(FRAME_PROPERTY_ADD_PAYLOAD)
#define FRAME_PROPERTY_ADD_ID_FIELD					   	(FRAME_PROPERTY_ADD_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_PROPERTY_ADD_PROPERTIES_COUNT_FIELD	   	(FRAME_PROPERTY_ADD_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_PROPERTY_ADD_PROPERTIES					(FRAME_PROPERTY_ADD_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define FRAME_PROPERTY_UPDATE_PAYLOAD					(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` | `propertiesCount` |  `frameProperties [...]` |
|:----------:|:---------:|:-----------------:|:------------------------:|
|    8bits   |   8bits   |        8bits      |      variable size       |
*/
#define FRAME_PROPERTY_UPDATE_ENTITY_ID_FIELD			(FRAME_PROPERTY_UPDATE_PAYLOAD)
#define FRAME_PROPERTY_UPDATE_ID_FIELD				   	(FRAME_PROPERTY_UPDATE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD   	(FRAME_PROPERTY_UPDATE_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_PROPERTY_UPDATE_PROPERTIES				(FRAME_PROPERTY_UPDATE_PROPERTIES_COUNT_FIELD + PROPERTIES_COUNT_FIELD_LENGTH)

#define FRAME_DATA_UPDATE_PAYLOAD						(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` |  `dataLength` |     `data`      |
|:----------:|:---------:|:-------------:|:---------------:|
|    8bits   |   8bits   |     8bits     |  variable size  |
*/
#define FRAME_DATA_UPDATE_ENTITY_ID_FIELD				(FRAME_DATA_UPDATE_PAYLOAD)
#define FRAME_DATA_UPDATE_ID_FIELD						(FRAME_DATA_UPDATE_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_DATA_UPDATE_DATA_LENGTH_FIELD				(FRAME_DATA_UPDATE_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_DATA_UPDATE_DATA_FIELD					(FRAME_DATA_UPDATE_DATA_LENGTH_FIELD + FRAME_DATA_LENGTH_FIELD_LENGTH)

#define FRAME_TX_PAYLOAD								(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` |  `dataLength` |     `data`      |
|:----------:|:---------:|:-------------:|:---------------:|
|    8bits   |   8bits   |     8bits     |  variable size  |
*/
#define FRAME_TX_ENTITY_ID_FIELD						(FRAME_TX_PAYLOAD)
#define FRAME_TX_ID_FIELD								(FRAME_TX_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_TX_DATA_LENGTH_FIELD						(FRAME_TX_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_TX_DATA_FIELD								(FRAME_TX_DATA_LENGTH_FIELD + FRAME_DATA_LENGTH_FIELD_LENGTH)

#define FRAME_CONSUME_PAYLOAD							(EVENT_PAYLOAD)
/*
| `entityID` | `frameID` |  `dataLength` |     `data`      |
|:----------:|:---------:|:-------------:|:---------------:|
|    8bits   |   8bits   |     8bits     |  variable size  |
*/
#define FRAME_CONSUME_ENTITY_ID_FIELD					(FRAME_CONSUME_PAYLOAD)
#define FRAME_CONSUME_ID_FIELD							(FRAME_CONSUME_ENTITY_ID_FIELD + ENTITY_ID_FIELD_LENGTH)
#define FRAME_CONSUME_DATA_LENGTH_FIELD					(FRAME_CONSUME_ID_FIELD + FRAME_ID_FIELD_LENGTH)
#define FRAME_CONSUME_DATA_FIELD						(FRAME_CONSUME_DATA_LENGTH_FIELD + FRAME_DATA_LENGTH_FIELD_LENGTH)

/* properties structure */
#define PROPERTY_DECLARATION_ID_FIELD				   (FIRST_BYTE)
#define PROPERTY_DECLARATION_UNIT_PREFIX_FIELD		   (PROPERTY_DECLARATION_ID_FIELD + PROPERTY_ID_FIELD_LENGTH)
#define PROPERTY_DECLARATION_UNIT_FIELD 			   (PROPERTY_DECLARATION_UNIT_PREFIX_FIELD + PROPERTY_UNIT_PREFIX_FIELD_LENGTH)
#define PROPERTY_DECLARATION_TYPE_FIELD				   (PROPERTY_DECLARATION_UNIT_FIELD + PROPERTY_UNIT_FIELD_LENGTH)
#define PROPERTY_DECLARATION_NAME_LENGTH_FIELD		   (PROPERTY_DECLARATION_TYPE_FIELD + PROPERTY_TYPE_FIELD_LENGTH)
#define PROPERTY_DECLARATION_VALUE_LENGTH_FIELD	       (PROPERTY_DECLARATION_NAME_LENGTH_FIELD + NAME_LENGTH_FIELD_LENGTH)

#define PROPERTY_UPDATE_ID_FIELD					   (FIRST_BYTE)
#define PROPERTY_UPDATE_VALUE_LENGTH_FIELD			   (PROPERTY_UPDATE_ID_FIELD + PROPERTY_ID_FIELD_LENGTH)


/* events types definitions */
#define EVENT_NODE_ADD 						           0x00
#define EVENT_NODE_PROPERTY_ADD 					   0x01
#define EVENT_NODE_PROPERTY_UPDATE 			           0x02
#define EVENT_NODE_REMOVE 					           0x03

#define EVENT_ENTITY_ADD 					           0x10
#define EVENT_ENTITY_PROPERTY_ADD			           0x11
#define EVENT_ENTITY_PROPERTY_UPDATE		           0x12
#define EVENT_ENTITY_REMOVE 				           0x13

#define EVENT_LINK_ADD 						           0x20
#define EVENT_LINK_PROPERTY_ADD                        0x21
#define EVENT_LINK_PROPERTY_UPDATE			           0x22
#define EVENT_LINK_REMOVE 					           0x23

#define EVENT_FRAME_PRODUCE 				           0x30
#define EVENT_FRAME_PROPERTY_ADD                       0x31
#define EVENT_FRAME_PROPERTY_UPDATE                    0x32
#define EVENT_FRAME_DATA_UPDATE	 			           0x33
#define EVENT_FRAME_TX 						           0x34
#define EVENT_FRAME_RX 						           0x35
#define EVENT_FRAME_CONSUME 				           0x36

/* properties types definitions */
#define TYPE_BOOLEAN				                   0x00
#define TYPE_INT8					                   0x01
#define TYPE_INT16					                   0x02
#define TYPE_INT32					                   0x03
#define TYPE_INT64					                   0x04
#define TYPE_UINT8					                   0x05
#define TYPE_UINT16					                   0x06
#define TYPE_UINT32					                   0x07
#define TYPE_UINT64					                   0x08
#define TYPE_FLOAT					                   0x09
#define TYPE_DOUBLE					                   0x0A
#define TYPE_ASCII_ARRAY			                   0x0B
#define TYPE_BYTE_ARRAY				                   0x0C
#define TYPE_INVALID				                   0x0D


/* properties SI units definitions */
#define UNIT_NONE					                   0x00
#define UNIT_METRE					                   0x01
#define UNIT_KILOGRAM				                   0x02
#define UNIT_SECOND  				                   0x03
#define UNIT_AMPERE					                   0x04
#define UNIT_KELVIN					                   0x05
#define UNIT_MOLE					                   0x06
#define UNIT_CANDELA				                   0x07
/* derivative units */
#define UNIT_RADIAN					                   0x08
#define UNIT_STERADIAN 				                   0x09
#define UNIT_HERTZ					                   0x0A
#define UNIT_NEWTON					                   0x0B
#define UNIT_PASCAL					                   0x0C
#define UNIT_JOULE					                   0x0D
#define UNIT_WATT					                   0x0E
#define UNIT_COULOMB				                   0x0F
#define UNIT_VOLT					                   0x10
#define UNIT_FARAD					                   0x11
#define UNIT_OHM					                   0x12
#define UNIT_SIEMENS				                   0x13
#define UNIT_WEBER					                   0x14
#define UNIT_TESLA					                   0x15
#define UNIT_HENRY					                   0x16
#define UNIT_DEGREECELSIUS			                   0x17
#define UNIT_LUMEN					                   0x18
#define UNIT_LUX					                   0x19
#define UNIT_BECQUEREL				                   0x1A
#define UNIT_GRAY					                   0x1B
#define UNIT_SIEVERT				                   0x1C
#define UNIT_KATAL					                   0x1D
/* generally useful units for radio communications */
#define UNIT_DB						                   0x1E
#define UNIT_DBW					                   0x1F
#define UNIT_DBMW					                   0x20

/* properties units prefixes */
#define PREFIX_YOTTA				                   0x00
#define PREFIX_ZETTA				                   0x01
#define PREFIX_EXA					                   0x02
#define PREFIX_PETA					                   0x03
#define PREFIX_TERA					                   0x04
#define PREFIX_GIGA					                   0x05
#define PREFIX_MEGA					                   0x06
#define PREFIX_KILO					                   0x07
#define PREFIX_HECTO				                   0x08
#define PREFIX_DECA					                   0x09
#define PREFIX_NONE					                   0x0A
#define PREFIX_DECI					                   0x0B
#define PREFIX_CENTI				                   0x0C
#define PREFIX_MILLI				                   0x0D
#define PREFIX_MICRO				                   0x0E
#define PREFIX_NANO					                   0x0F
#define PREFIX_PICO					                   0x10
#define PREFIX_FEMTO				                   0x11
#define PREFIX_ATTO					                   0x12
#define PREFIX_ZEPTO				                   0x13
#define PREFIX_YOCTO				                   0x14

/* common values */
#define VALUE_FALSE					                   0x00
#define VALUE_TRUE					                   0x01

/* reserved property names */
#define PROPERTY_NAME_ENTITY_LEVEL                      "osi_level"
#define PROPERTY_NAME_FRAME_DISSECTOR				"ws_dissector"
#define PROPERTY_FRAME_DISSECTOR_UNDEFINED  "undefined"
#define PROPERTY_UNKNOWN_NAME								"unknown property"

#if	defined(__BUILDING_WIRESHARK_DISSECTOR__) || defined(__BUILDING_INFRASTRUCTURE__)
/* Wireshark link layer type (user space) */
#define SENSORLAB_LINK_LAYER_TYPE	        147

/* Wireshark tap output filename */
#define SENSORLAB_TAP_OUTPUT_FILENAME			"experiment-%s.json"

/* Wireshark dictionaries linking identifiers to names, e.g. EVENT_NODE_ADD => NodeAdd */
static const value_string event_names_dictionary[] = {
		{	EVENT_NODE_ADD			     , 		"NodeAdd"			},
		{	EVENT_NODE_PROPERTY_ADD		, 	"NodePropertyAdd"			},
		{	EVENT_NODE_PROPERTY_UPDATE, 	"NodePropertyUpdate"		},
		{	EVENT_NODE_REMOVE		     , 	  "NodeRemove"		},
		{	EVENT_ENTITY_ADD		     ,	  "EntityAdd"			},
		{	EVENT_ENTITY_PROPERTY_ADD,    "EntityPropertyAdd"		},
		{	EVENT_ENTITY_PROPERTY_UPDATE, "EntityPropertyUpdate"		},
		{	EVENT_ENTITY_REMOVE		     ,	"EntityRemove"		},
		{	EVENT_LINK_ADD			     ,		"LinkAdd"			},
		{	EVENT_LINK_PROPERTY_ADD   ,		"LinkPropertyAdd"		},
		{	EVENT_LINK_PROPERTY_UPDATE,		"LinkPropertyUpdate"		},
		{	EVENT_LINK_REMOVE		     ,		"LinkRemove"		},
		{	EVENT_FRAME_PRODUCE		     ,		"FrameProduce"		},
		{	EVENT_FRAME_PROPERTY_ADD	 ,		"FramePropertyAdd"		},
		{	EVENT_FRAME_PROPERTY_UPDATE	 ,		"FramePropertyUpdate"		},
		{	EVENT_FRAME_DATA_UPDATE	     ,		"FrameDataUpdate"		},
		{	EVENT_FRAME_TX			     ,		"FrameTX"			},
		{	EVENT_FRAME_RX			     ,		"FrameRX"			},
		{	EVENT_FRAME_CONSUME		     ,		"FrameConsume"		},
		{ 	0                            ,      NULL                }
};
static const value_string type_names_dictionary[] = {
		{	TYPE_BOOLEAN				     , 		"Boolean"					},
		{	TYPE_INT8					     , 		"Integer(8bits)"			},
		{	TYPE_INT16					     , 		"Integer(16bits)"			},
		{	TYPE_INT32					     , 		"Integer(32bits)"			},
		{	TYPE_INT64					     , 		"Integer(64bits)"			},
		{	TYPE_UINT8					     , 		"Unsigned Integer(8bits)"	},
		{	TYPE_UINT16					     , 		"Unsigned Integer(16bits)"	},
		{	TYPE_UINT32					     , 		"Unsigned Integer(32bits)"	},
		{	TYPE_UINT64					     , 		"Unsigned Integer(64bits)"	},
		{	TYPE_FLOAT					     , 		"Float(32bits)"				},
		{	TYPE_DOUBLE					     , 		"Double"					},
		{	TYPE_ASCII_ARRAY			     , 		"ASCII Array"				},
		{	TYPE_BYTE_ARRAY				     , 		"Byte Array"				},
		{ 	0                            	 ,      NULL                		}
};
static const value_string unit_names_dictionary[] = {
		{	UNIT_NONE				     , 		""					},
		{	UNIT_METRE				     , 		"m"					},
		{	UNIT_KILOGRAM			     , 		"kg"				},
		{	UNIT_SECOND 			     , 		"s"					},
		{	UNIT_AMPERE				     , 		"A"					},
		{	UNIT_KELVIN				     , 		"K"					},
		{	UNIT_MOLE				     , 		"mol"				},
		{	UNIT_CANDELA			     , 		"cd"				},
		{	UNIT_RADIAN				     , 		"rad"				},
		{	UNIT_STERADIAN			     , 		"sr"				},
		{	UNIT_HERTZ				     , 		"Hz"				},
		{	UNIT_NEWTON				     , 		"N"					},
		{	UNIT_PASCAL				     , 		"Pa"				},
		{	UNIT_JOULE				     , 		"J"					},
		{	UNIT_WATT				     , 		"W"					},
		{	UNIT_COULOMB			     , 		"C"					},
		{	UNIT_VOLT				     , 		"V"					},
		{	UNIT_FARAD				     , 		"F"					},
		{	UNIT_OHM				     , 		"ohm"				},
		{	UNIT_SIEMENS			     , 		"S"					},
		{	UNIT_WEBER				     , 		"Wb"				},
		{	UNIT_TESLA				     , 		"T"					},
		{	UNIT_HENRY				     , 		"H"					},
		{	UNIT_DEGREECELSIUS		     , 		"D.Celsius"			},
		{	UNIT_LUMEN				     , 		"lm"				},
		{	UNIT_LUX				     , 		"lx"				},
		{	UNIT_BECQUEREL			     , 		"Bq"				},
		{	UNIT_GRAY				     , 		"Gy"				},
		{	UNIT_SIEVERT			     , 		"Sv"				},
		{	UNIT_KATAL				     , 		"kat"				},
		{	UNIT_DB					     , 		"dB"				},
		{	UNIT_DBW				     , 		"dBW"				},
		{	UNIT_DBMW				     , 		"dBm"				},
		{ 	0 							 ,       NULL 				}
};

static const value_string prefix_names_dictionary[] = {
		{ 	PREFIX_YOTTA			     , 		"Y"					},
		{	PREFIX_ZETTA                 ,		"Z"					},
		{	PREFIX_EXA                   ,		"E"					},
		{	PREFIX_PETA                  ,		"P"					},
		{	PREFIX_TERA                  ,		"T"					},
		{	PREFIX_GIGA                  ,		"G"					},
		{	PREFIX_MEGA                  ,		"M"					},
		{	PREFIX_KILO                  ,		"k"					},
		{	PREFIX_HECTO                 ,		"h"					},
		{	PREFIX_DECA                  ,		"da"				},
		{	PREFIX_NONE                  ,		""					},
		{	PREFIX_DECI                  ,		"d"					},
		{	PREFIX_CENTI                 ,		"c"					},
		{	PREFIX_MILLI                 ,		"m"					},
		{	PREFIX_MICRO                 ,		"u"					},
		{	PREFIX_NANO                  ,		"n"					},
		{	PREFIX_PICO                  ,		"p"					},
		{	PREFIX_FEMTO                 ,		"f"					},
		{	PREFIX_ATTO                  ,		"a"					},
		{	PREFIX_ZEPTO                 ,		"z"					},
		{	PREFIX_YOCTO                 ,		"y"					},
		{ 	0 							 ,      NULL 				}
};

static const value_string value_names_dictionary[] = {
		{	VALUE_TRUE				     ,		"true"				},
		{	VALUE_FALSE				     ,		"false"				},
		{ 	0 							 ,       NULL 				}
};

#endif /* __BUILDING_WIRESHARK_DISSECTOR__ || __BUILDING_INFRASTRUCTURE__ */

#endif /* PACKET_SENSORLABS_H_ */
