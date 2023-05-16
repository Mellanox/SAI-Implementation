/////// from flex_acl_keys.c //////

#include <sx/sdk/sx_api.h>
#include <sx/sdk/sx_api_acl.h>
#include <syslog.h>

#include <complib/sx_log.h>

#undef __MODULE__
#define __MODULE__ FXAPI_VALIDATION
static sx_verbosity_level_t LOG_VAR_NAME(__MODULE__) = SX_VERBOSITY_LEVEL_WARNING;

#define FX_LOG(L, FMT, ...)                                                         \
    do {                                                                            \
        SX_LOG(L, "[%s] %s:%i: " FMT, __FILE__, __func__,__LINE__, ## __VA_ARGS__); \
    } while (0)

// can fold some of this into the compiler to do early semantic checks
// for valid const table entries

/************************************************
 *  Local function declarations
 ***********************************************/
char * key_dictionary[FLEX_ACL_KEY_LAST + 1] = {
    [FLEX_ACL_KEY_DIP] = "DIP", /**< size:32, IPV4/IPV6 destination IP address */
    [FLEX_ACL_KEY_SIP] = "SIP", /**< size:32, IPV4/IPV6 source IP address */
    [FLEX_ACL_KEY_DSCP] = "DSCP", /**< size:6, DSCP */
    [FLEX_ACL_KEY_RW_DSCP] = "RW_DSCP", /**< size:1,  -0 packet is transmitted with DSCP at end of control pipe 1 - DSCP gets encoded from QoSi */
    [FLEX_ACL_KEY_ECN] = "ECN", /**< size:2, ECN    */
    [FLEX_ACL_KEY_IP_FRAGMENTED] = "IP_FRAGMENTED", /**< size:1, When set means that the packet is segment os a fragmented packets.    */
    [FLEX_ACL_KEY_IP_DONT_FRAGMENT] = "IP_DONT_FRAGMENT", /**< size:1, When set means that the packet should not be fragmented.    */
    [FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST] = "IP_FRAGMENT_NOT_FIRST", /**< size:1, When set means that the segment is not first segment of fragmented packets.    */
    [FLEX_ACL_KEY_IP_PACKET_LENGTH] = "IP_PACKET_LENGTH", /**< size:16, IPV4/6 header length   */
    [FLEX_ACL_KEY_IP_OK] = "IP_OK", /**< size:1, IPV4/6 header validation checked OK    */
    [FLEX_ACL_KEY_IS_ARP] = "IS_ARP", /**< size:1, According to Ether type - does not include RARP.    */
    [FLEX_ACL_KEY_IP_OPT] = "IP_OPT", /**< size:1, Relevant for IPV4    */
    [FLEX_ACL_KEY_IS_IP_V4] = "IS_IP_V4", /**< size:1,  */
    [FLEX_ACL_KEY_L3_TYPE] = "L3_TYPE", /**< size:2, 1 - IPV4 */
    [FLEX_ACL_KEY_TTL] = "TTL", /**< size:8,  */
    [FLEX_ACL_KEY_TTL_OK] = "TTL_OK", /**< size:1,  */
    [FLEX_ACL_KEY_L4_DESTINATION_PORT] = "L4_DEST_PORT", /**< size:16,  */
    [FLEX_ACL_KEY_L4_OK] = "L4_OK", /**< size:1,  */
    [FLEX_ACL_KEY_L4_SOURCE_PORT] = "L4_SRC_PORT", /**< size:16,  */
    [FLEX_ACL_KEY_L4_TYPE] = "L4_TYPE", /**< size:4, Bit 0 - TCP */
    [FLEX_ACL_KEY_TCP_CONTROL] = "TCP_CONTROL", /**< size:6, All the TCP control bits from header  */
    [FLEX_ACL_KEY_TCP_ECN] = "TCP_ECN", /**< size:3, TCP ECN bits  */
    [FLEX_ACL_KEY_DMAC] = "DMAC", /**< size:48, Destination MAC address */
    [FLEX_ACL_KEY_L2_DMAC_TYPE] = "L2_DMAC_TYPE", /**< size:2, 0 - Mc */
    [FLEX_ACL_KEY_ETHERTYPE] = "ETHERTYPE", /**< size:16,  */
    [FLEX_ACL_KEY_RW_PCP] = "RW_PCP", /**< size:1, 0 - The packet gets transmitted with VLAN.PCP and VLAN.DEI */
    [FLEX_ACL_KEY_SMAC] = "SMAC", /**< size:48, Source MAC address   */
    [FLEX_ACL_KEY_DEI] = "DEI", /**< size:1,  */
    [FLEX_ACL_KEY_PCP] = "PCP", /**< size:3,  */
    [FLEX_ACL_KEY_VLAN_TAGGED] = "VLAN_TAGGED", /**< size:1, Indicates whether the packet enter the chip with or without VLAN tag */
    [FLEX_ACL_KEY_VLAN_VALID] = "VLAN_VALID", /**< size:1,  */
    [FLEX_ACL_KEY_VLAN_ID] = "VLAN_ID", /**< size:12,  */
    [FLEX_ACL_KEY_COLOR] = "COLOR", /**< size:2, Internal color/drop precedence of the packet of the packet */
    [FLEX_ACL_KEY_DST_PORT] = "DST_PORT", /**< size:16, System destination port */
    [FLEX_ACL_KEY_SWITCH_PRIO] = "SWITCH_PRIO", /**< size:4, Key of QOS indicator */
    [FLEX_ACL_KEY_SRC_PORT] = "SRC_PORT", /**< size:32, System source port or LAG */
    [FLEX_ACL_KEY_DMAC_IS_UC] = "DMAC_IS_UC", /**< size:1,  0 - MC 1 - UC */
    [FLEX_ACL_KEY_BUFF] = "BUFF", /**< size:4, The priority group of the packet as classified when entered/enqued the chip */
    [FLEX_ACL_KEY_IP_PROTO] = "IP_PROTO", /**< size:8, IPV6 header next protocol    */
    [FLEX_ACL_KEY_L4_PORT_RANGE] = "L4_PORT_RANGE", /**< size:16,  */
    [FLEX_ACL_KEY_DIPV6] = "DIPV6", /**< size:32, IPV4/IPV6 destination IP address */
    [FLEX_ACL_KEY_SIPV6] = "SIPV6", /**< size:32, IPV4/IPV6 source IP address */
    [FLEX_ACL_KEY_IRIF] = "IRIF", /**< size:10, Ingress router interface */
    [FLEX_ACL_KEY_ERIF] = "ERIF", /**< size:10, Ingress router interface */
    [FLEX_ACL_KEY_RX_LIST] = "RX_LIST", /**< size:64,  */
    [FLEX_ACL_KEY_L4_TYPE_EXTENDED] = "L4_TYPE_EXTENDED", /**< size:4, 1 - None */
    [FLEX_ACL_KEY_TUNNEL_TYPE] = "TUNNEL_TYPE",
    [FLEX_ACL_KEY_TUNNEL_NVE_TYPE] = "NVE_TUNNEL_VECTOR",
    [FLEX_ACL_KEY_VNI_KEY] = "VNI",
    [FLEX_ACL_KEY_GRE_KEY] = "GRE_KEY",
    [FLEX_ACL_KEY_GRE_PROTOCOL] = "GRE_PROTOCOL",
    [FLEX_ACL_KEY_USER_TOKEN] = "USER_TOKEN",
    [FLEX_ACL_KEY_IPV6_EXTENSION_HEADERS] = "IPV6_EXT_HDRS",
    [FLEX_ACL_KEY_IPV6_EXTENSION_HEADER_EXISTS] = "IPV6_EXT_HDR_EXISTS",
    [FLEX_ACL_KEY_MPLS_LABEL_ID_1] = "MPLS_LABEL_ID_1", /**< size:20. Outermost MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABEL_ID_2] = "MPLS_LABEL_ID_2", /**< size:20. MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABEL_ID_3] = "MPLS_LABEL_ID_3", /**< size:20. MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABEL_ID_4] = "MPLS_LABEL_ID_4", /**< size:20. MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABEL_ID_5] = "MPLS_LABEL_ID_5", /**< size:20. MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABEL_ID_6] = "MPLS_LABEL_ID_6", /**< size:20. Innermost MPLS label. */
    [FLEX_ACL_KEY_MPLS_LABELS_VALID] = "MPLS_LABELS_VALID",
    [FLEX_ACL_KEY_EXP] = "EXP",
    [FLEX_ACL_KEY_BOS] = "BoS",
    [FLEX_ACL_KEY_MPLS_TTL] = "MPLS_TTL",
    [FLEX_ACL_KEY_MPLS_CONTROL_WORD] = "MPLS_CONTROL_WORD",
    [FLEX_ACL_KEY_MPLS_CONTROL_WORD_VALID] = "MPLS_CONTROL_WORD_VALID",
    [FLEX_ACL_KEY_IS_MPLS] = "IS_MPLS",
    [FLEX_ACL_KEY_RW_EXP] = "RW_EXP",
    [FLEX_ACL_KEY_INNER_L3_TYPE] = "INNER_L3_TYPE",
    [FLEX_ACL_KEY_INNER_L4_OK] = "INNER_L4_OK",
    [FLEX_ACL_KEY_INNER_TTL_OK] = "INNER_TTL_OK",
    [FLEX_ACL_KEY_INNER_IP_PROTO] = "INNER_IP_PROTO",
    [FLEX_ACL_KEY_INNER_DIP] = "INNER_DIP",
    [FLEX_ACL_KEY_INNER_SIP] = "INNER_SIP",
    [FLEX_ACL_KEY_INNER_SIPV6] = "INNER_SIPV6",
    [FLEX_ACL_KEY_INNER_DIPV6] = "INNER_DIPV6",
    [FLEX_ACL_KEY_INNER_IP_OK] = "INNER_IP_OK",
    [FLEX_ACL_KEY_INNER_VLAN_VALID] = "INNER_VLAN_VALID",
    [FLEX_ACL_KEY_INNER_SMAC] = "INNER_SMAC",
    [FLEX_ACL_KEY_INNER_DMAC] = "INNER_DMAC",
    [FLEX_ACL_KEY_INNER_L4_DESTINATION_PORT] = "INNER_L4_DEST_PORT",
    [FLEX_ACL_KEY_INNER_L4_SOURCE_PORT] = "INNER_L4_SRC_PORT",
    [FLEX_ACL_KEY_INNER_DEI] = "INNER_DEI",
    [FLEX_ACL_KEY_INNER_PCP] = "INNER_PCP",
    [FLEX_ACL_KEY_INNER_ETHERTYPE] = "INNER_ETHERTYPE",
    [FLEX_ACL_KEY_INNER_DSCP] = "INNER_DSCP",
    [FLEX_ACL_KEY_INNER_ECN] = "INNER_ECN",
    [FLEX_ACL_KEY_VIRTUAL_ROUTER] = "VIRTUAL_ROUTER",
    [FLEX_ACL_KEY_DISCARD_STATE] = "DISCARD_STATE",
    [FLEX_ACL_KEY_IS_TRAPPED] = "IS_TRAPPED",
    [FLEX_ACL_KEY_RX_PORT_LIST] = "RX_PORT_LIST", /**< size:64,  */
    [FLEX_ACL_KEY_TX_PORT_LIST] = "TX_PORT_LIST", /**< size:64,  */
    [FLEX_ACL_KEY_IS_ROUTED] = "IS_ROUTED",
    [FLEX_ACL_KEY_CUSTOM_BYTE_0] = "CUSTOM_BYTES_0",
    [FLEX_ACL_KEY_CUSTOM_BYTE_1] = "CUSTOM_BYTES_1",
    [FLEX_ACL_KEY_CUSTOM_BYTE_2] = "CUSTOM_BYTES_2",
    [FLEX_ACL_KEY_CUSTOM_BYTE_3] = "CUSTOM_BYTES_3",
    [FLEX_ACL_KEY_CUSTOM_BYTE_4] = "CUSTOM_BYTES_4",
    [FLEX_ACL_KEY_CUSTOM_BYTE_5] = "CUSTOM_BYTES_5",
    [FLEX_ACL_KEY_CUSTOM_BYTE_6] = "CUSTOM_BYTES_6",
    [FLEX_ACL_KEY_CUSTOM_BYTE_7] = "CUSTOM_BYTES_7",
    [FLEX_ACL_KEY_CUSTOM_BYTE_8] = "CUSTOM_BYTES_8",
    [FLEX_ACL_KEY_CUSTOM_BYTE_9] = "CUSTOM_BYTES_9",
    [FLEX_ACL_KEY_CUSTOM_BYTE_10] = "CUSTOM_BYTES_10",
    [FLEX_ACL_KEY_CUSTOM_BYTE_11] = "CUSTOM_BYTES_11",
    [FLEX_ACL_KEY_CUSTOM_BYTE_12] = "CUSTOM_BYTES_12",
    [FLEX_ACL_KEY_CUSTOM_BYTE_13] = "CUSTOM_BYTES_13",
    [FLEX_ACL_KEY_CUSTOM_BYTE_14] = "CUSTOM_BYTES_14",
    [FLEX_ACL_KEY_CUSTOM_BYTE_15] = "CUSTOM_BYTES_15",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_0] = "ETHERNET_PAYLOAD_DWORD_0",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_1] = "ETHERNET_PAYLOAD_DWORD_1",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_2] = "ETHERNET_PAYLOAD_DWORD_2",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_3] = "ETHERNET_PAYLOAD_DWORD_3",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_4] = "ETHERNET_PAYLOAD_DWORD_4",
    [FLEX_ACL_KEY_ETHERNET_PAYLOAD_DWORD_5] = "ETHERNET_PAYLOAD_DWORD_5",
    [FLEX_ACL_KEY_ROCE_DEST_QP] = "ROCE_DEST_QP",
    [FLEX_ACL_KEY_ROCE_PKEY] = "ROCE_PKEY",
    [FLEX_ACL_KEY_ROCE_BTH_OPCODE] = "ROCE_BTH_OPCODE",
    [FLEX_ACL_KEY_DWORD_0_VALID] = "DWORD_0_VALID",
    [FLEX_ACL_KEY_DWORD_1_VALID] = "DWORD_1_VALID",
    [FLEX_ACL_KEY_DWORD_2_VALID] = "DWORD_2_VALID",
    [FLEX_ACL_KEY_DWORD_3_VALID] = "DWORD_3_VALID",
    [FLEX_ACL_KEY_DWORD_4_VALID] = "DWORD_4_VALID",
    [FLEX_ACL_KEY_DWORD_5_VALID] = "DWORD_5_VALID",
    [FLEX_ACL_KEY_LAST] = "LAST",
};

#define KEY_ID_2STR(key_id)          \
    ((key_id) < FLEX_ACL_KEY_LAST && \
     key_dictionary[(key_id)]) ? key_dictionary[(key_id)] : "invalid"

typedef boolean_t (*is_key_value_valid_t)(sx_flex_acl_key_desc_t *key);
/* Key validation function declarations */
static boolean_t is_dscp_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_color_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_ip_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_ipv6_extension_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_tcp_control_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_l4_type_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_3bits_field_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_vlan_id_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_bit_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_2bits_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_nible_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_l2_dmac_type_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_l3_type_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_label_id_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_mpls_labels_valid_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_rif_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_virtual_router_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_tunnel_type_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_tunnel_nve_type_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_l4_type_extended_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_src_port_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_dst_port_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_buff_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_l4_port_range_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_rx_list_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_port_list_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_user_token_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_discard_state_valid(sx_flex_acl_key_desc_t *key);
static boolean_t is_qp_valid(sx_flex_acl_key_desc_t *key);

#define BOOLEAN_MASK_CHECK(key_name, valid_ind, out_label)                                                          \
    if ((key->mask.key_name != TRUE) && (key->mask.key_name != FALSE)) {                                            \
        FX_LOG(SX_LOG_ERROR,"ACL : Invalid boolean mask for %s. mask :%x \n", KEY_ID_2STR(key->key_id), key->mask.key_name); \
        valid_ind = FALSE;                                                                                          \
        goto out_label;                                                                                             \
    }                                                                                                               \
    valid_ind = TRUE

#define AVOID_VALIDATION_IF_MASK_FALSE(key_name, out_label) \
    if (key->mask.key_name == FALSE)                        \
        goto out_label

/***********************************************
*  Key validation functions
***********************************************/
static boolean_t is_qp_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    /* qp is 24 bits long. */
    if (key->key.dest_qp > 0xFFFFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"dest_qp key value :%d is not valid.\n", key->key.dest_qp);
        goto out;
    }

    if (key->mask.dest_qp > 0xFFFFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"dest_qp mask value :%d is not valid.\n", key->mask.dest_qp);
    }

out:
    return is_valid;
}

static boolean_t is_dscp_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    /* DSCP is 6 bits long. */
    if (key->key.dscp > 0x3F) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"dscp key value :%d is not valid.\n", key->key.dscp);
        goto out;
    }

    if (key->mask.dscp > 0x3F) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"dscp mask value :%d is not valid.\n", key->mask.dscp);
    }

out:
    return is_valid;
}

static boolean_t is_color_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(color, is_valid, out);

    if (key->key.color >= SX_ACL_FLEX_COLOR_LAST) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"color key value :%d is not valid.\n", key->key.color);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_ip_version_valid(sx_ip_addr_t    key_ip,
                                     sx_ip_addr_t    mask_ip,
                                     sx_ip_version_t ip_version,
                                     boolean_t       is_sip)
{
    boolean_t is_valid = TRUE;

    if (key_ip.version != ip_version) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key %s %s does not have proper IP version .\n", ip_version == SX_IP_VERSION_IPV4 ? "IPV4" : "IPV6",
                   is_sip ? "SIP" : "DIP");
    }
    if (mask_ip.version != ip_version) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Mask %s %s does not have proper IP version .\n",
                   ip_version == SX_IP_VERSION_IPV4 ? "IPV4" : "IPV6",
                   is_sip ? "SIP" : "DIP");
    }

    return is_valid;
}


static boolean_t is_ip_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    switch (key->key_id) {
    case FLEX_ACL_KEY_SIP:
        is_valid = is_ip_version_valid(key->key.sip, key->mask.sip, SX_IP_VERSION_IPV4, TRUE);
        break;

    case FLEX_ACL_KEY_INNER_SIP:
        is_valid = is_ip_version_valid(key->key.inner_sip, key->mask.inner_sip, SX_IP_VERSION_IPV4, FALSE);
        break;

    case FLEX_ACL_KEY_DIP:
        is_valid = is_ip_version_valid(key->key.dip, key->mask.dip, SX_IP_VERSION_IPV4, FALSE);
        break;

    case FLEX_ACL_KEY_INNER_DIP:
        is_valid = is_ip_version_valid(key->key.inner_dip, key->mask.inner_dip, SX_IP_VERSION_IPV4, FALSE);
        break;

    case FLEX_ACL_KEY_DIPV6:
        is_valid = is_ip_version_valid(key->key.dipv6, key->mask.dipv6, SX_IP_VERSION_IPV6, FALSE);
        break;

    case FLEX_ACL_KEY_SIPV6:
        is_valid = is_ip_version_valid(key->key.sipv6, key->mask.sipv6, SX_IP_VERSION_IPV6, TRUE);
        break;

    case FLEX_ACL_KEY_INNER_SIPV6:
        is_valid = is_ip_version_valid(key->key.inner_sipv6, key->mask.inner_sipv6, SX_IP_VERSION_IPV6, TRUE);
        break;

    case FLEX_ACL_KEY_INNER_DIPV6:
        is_valid = is_ip_version_valid(key->key.inner_dipv6, key->mask.inner_dipv6, SX_IP_VERSION_IPV6, FALSE);
        break;

    default:
        FX_LOG(SX_LOG_ERROR,"Key %s is not ipv4 and not ipv6 sip or dip\n", KEY_ID_2STR(key->key_id));
        is_valid = FALSE;

        break;
    }
    return is_valid;
}


/************************************************
 *  Key validation function array
 ***********************************************/

static is_key_value_valid_t keys_validation[FLEX_ACL_KEY_LAST] = {
    [FLEX_ACL_KEY_SIP] = is_ip_valid,
    [FLEX_ACL_KEY_DIP] = is_ip_valid,
    [FLEX_ACL_KEY_COLOR] = is_color_valid,
    [FLEX_ACL_KEY_DSCP] = is_dscp_valid,
    [FLEX_ACL_KEY_RW_DSCP] = is_bit_valid,
    [FLEX_ACL_KEY_ECN] = is_2bits_valid,
    [FLEX_ACL_KEY_IP_FRAGMENTED] = is_bit_valid,
    [FLEX_ACL_KEY_IP_DONT_FRAGMENT] = is_bit_valid,
    [FLEX_ACL_KEY_IP_FRAGMENT_NOT_FIRST] = is_bit_valid,
    [FLEX_ACL_KEY_IP_OK] = is_bit_valid,
    [FLEX_ACL_KEY_IS_ARP] = is_bit_valid,
    [FLEX_ACL_KEY_IP_OPT] = is_bit_valid,
    [FLEX_ACL_KEY_IS_IP_V4] = is_bit_valid,
    [FLEX_ACL_KEY_L3_TYPE] = is_l3_type_valid,
    [FLEX_ACL_KEY_TTL_OK] = is_bit_valid,
    [FLEX_ACL_KEY_L4_OK] = is_bit_valid,
    [FLEX_ACL_KEY_L4_TYPE] = is_l4_type_valid,
    [FLEX_ACL_KEY_TCP_CONTROL] = is_tcp_control_valid,
    [FLEX_ACL_KEY_TCP_ECN] = is_3bits_field_valid,
    [FLEX_ACL_KEY_L2_DMAC_TYPE] = is_l2_dmac_type_valid,
    [FLEX_ACL_KEY_SRC_PORT] = is_src_port_valid,
    [FLEX_ACL_KEY_DST_PORT] = is_dst_port_valid,
    [FLEX_ACL_KEY_RW_PCP] = is_bit_valid,
    [FLEX_ACL_KEY_DEI] = is_bit_valid,
    [FLEX_ACL_KEY_PCP] = is_3bits_field_valid,
    [FLEX_ACL_KEY_INNER_DEI] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_PCP] = is_3bits_field_valid,
    [FLEX_ACL_KEY_VLAN_TAGGED] = is_bit_valid,
    [FLEX_ACL_KEY_VLAN_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_VLAN_ID] = is_vlan_id_valid,
    [FLEX_ACL_KEY_SWITCH_PRIO] = is_nible_valid,
    [FLEX_ACL_KEY_DMAC_IS_UC] = is_bit_valid,
    [FLEX_ACL_KEY_BUFF] = is_buff_valid,
    [FLEX_ACL_KEY_L4_PORT_RANGE] = is_l4_port_range_valid,
    [FLEX_ACL_KEY_SIPV6] = is_ip_valid,
    [FLEX_ACL_KEY_DIPV6] = is_ip_valid,
    [FLEX_ACL_KEY_INNER_SIPV6] = is_ip_valid,
    [FLEX_ACL_KEY_INNER_DIPV6] = is_ip_valid,
    [FLEX_ACL_KEY_IRIF] = is_rif_valid,
    [FLEX_ACL_KEY_ERIF] = is_rif_valid,
    [FLEX_ACL_KEY_VIRTUAL_ROUTER] = is_virtual_router_valid,
    [FLEX_ACL_KEY_TUNNEL_TYPE] = is_tunnel_type_valid,
    [FLEX_ACL_KEY_TUNNEL_NVE_TYPE] = is_tunnel_nve_type_valid,
    [FLEX_ACL_KEY_L4_TYPE_EXTENDED] = is_l4_type_extended_valid,
    [FLEX_ACL_KEY_RX_LIST] = is_rx_list_valid,
    [FLEX_ACL_KEY_IPV6_EXTENSION_HEADERS] = is_ipv6_extension_valid,
    [FLEX_ACL_KEY_IPV6_EXTENSION_HEADER_EXISTS] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_DIP] = is_ip_valid,
    [FLEX_ACL_KEY_INNER_SIP] = is_ip_valid,
    [FLEX_ACL_KEY_INNER_TTL_OK] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_L4_OK] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_IP_OK] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_VLAN_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_INNER_L3_TYPE] = is_l3_type_valid,
    [FLEX_ACL_KEY_USER_TOKEN] = is_user_token_valid,
    [FLEX_ACL_KEY_DISCARD_STATE] = is_discard_state_valid,
    [FLEX_ACL_KEY_IS_TRAPPED] = is_bit_valid,
    [FLEX_ACL_KEY_IS_MPLS] = is_bit_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_1] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_2] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_3] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_4] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_5] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABEL_ID_6] = is_label_id_valid,
    [FLEX_ACL_KEY_MPLS_LABELS_VALID] = is_mpls_labels_valid_valid,
    [FLEX_ACL_KEY_RW_EXP] = is_bit_valid,
    [FLEX_ACL_KEY_EXP] = is_3bits_field_valid,
    [FLEX_ACL_KEY_BOS] = is_bit_valid,
    [FLEX_ACL_KEY_RX_PORT_LIST] = is_port_list_valid,
    [FLEX_ACL_KEY_TX_PORT_LIST] = is_port_list_valid,
    [FLEX_ACL_KEY_IS_ROUTED] = is_bit_valid,
    [FLEX_ACL_KEY_ROCE_DEST_QP] = is_qp_valid,
    [FLEX_ACL_KEY_DWORD_0_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_DWORD_1_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_DWORD_2_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_DWORD_3_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_DWORD_4_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_DWORD_5_VALID] = is_bit_valid,
    [FLEX_ACL_KEY_MPLS_CONTROL_WORD_VALID] = is_bit_valid,
};

static boolean_t is_ipv6_extension_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;
    uint32_t  i;

    BOOLEAN_MASK_CHECK(ipv6_extension_headers, is_valid, out);

    if (key->key.ipv6_extension_headers.extension_headers_cnt > SX_FLEX_ACL_IPV6_EXTENSION_HEADER_LAST) {
        FX_LOG(SX_LOG_ERROR,"Invalid number of header extensions %d. Max number of extension : %d\n",
                   key->key.ipv6_extension_headers.extension_headers_cnt, SX_FLEX_ACL_IPV6_EXTENSION_HEADER_LAST);
        is_valid = FALSE;
        goto out;
    }
    for (i = 0; i < key->key.ipv6_extension_headers.extension_headers_cnt; i++) {
        if (key->key.ipv6_extension_headers.extension_headers_list[i] >= SX_FLEX_ACL_IPV6_EXTENSION_HEADER_LAST) {
            FX_LOG(SX_LOG_ERROR,"Invalid header extensions %u\n",
                       key->key.ipv6_extension_headers.extension_headers_list[i]);
            is_valid = FALSE;
            goto out;
        }
    }

out:
    return is_valid;
}

static boolean_t is_tcp_control_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    /* tcp control is 6 bits long. */
    if (key->mask.tcp_control > 0x3f) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"tcp_control mask value :%x is not valid.\n", key->mask.tcp_control);
        goto out;
    }

    if (key->key.tcp_control > 0x3f) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"tcp_control key value :%x is not valid.\n", key->key.tcp_control);
    }

out:
    return is_valid;
}

static boolean_t is_l4_type_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(l4_type, is_valid, out);

    if (key->key.l4_type > SX_ACL_L4_TYPE_MAX) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"l4 type valid key value is not valid. value:%#x\n", key->key.l4_type);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_3bits_field_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;
    uint8_t   mask_val, key_val;

    mask_val = *((uint8_t*)&(key->mask));
    key_val = *((uint8_t*)&(key->key));

    if (mask_val > 7) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s mask value is to big. value:%x max value :%x\n", KEY_ID_2STR(key->key_id),
                   mask_val, 7);
        goto out;
    }

    if (key_val > 7) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s key value is to big. value:%x max value :%x\n", KEY_ID_2STR(key->key_id),
                   key_val, 7);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_vlan_id_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    if (key->mask.vlan_id > 0xFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"vlan id type mask value :%#x is not valid.\n", key->mask.vlan_id);
        goto out;
    }

    if (key->key.vlan_id > 0xFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"vlan id type key value :%#x is not valid.\n", key->key.vlan_id);
    }

out:
    return is_valid;
}

static boolean_t is_bit_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;
    uint8_t   mask_val, key_val;

    mask_val = *((uint8_t*)&(key->mask));
    key_val = *((uint8_t*)&(key->key));

    if ((mask_val != 1) && (mask_val != 0)) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"ACL : mask is not valid for %s. mask:%x \n", KEY_ID_2STR(key->key_id),
                   mask_val);
        goto out;
    }

    if (key_val > 1) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s bit key value is to big value:%x.\n", KEY_ID_2STR(key->key_id), key_val);
    }

out:
    return is_valid;
}

static boolean_t is_2bits_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;
    uint8_t   mask_val, key_val;

    mask_val = *((uint8_t*)&(key->mask));
    key_val = *((uint8_t*)&(key->key));

    if (mask_val > 3) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s mask value is to big. value:%#x \n", KEY_ID_2STR(key->key_id), mask_val);
        goto out;
    }

    if (key_val > 3) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s key value is to big. value:%#x \n", KEY_ID_2STR(key->key_id), key_val);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_nible_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;
    uint8_t   mask_val, key_val;

    mask_val = *((uint8_t*)&(key->mask));
    key_val = *((uint8_t*)&(key->key));

    if (mask_val > 0xf) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s mask value is to big. value:%#x \n", KEY_ID_2STR(key->key_id), mask_val);
        goto out;
    }

    if (key_val > 0xf) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Key :%s key value is to big. value:%#x \n", KEY_ID_2STR(key->key_id), key_val);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_l2_dmac_type_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(l2_dmac_type, is_valid, out);

    if (key->key.l2_dmac_type > SX_ACL_L2_DMAC_TYPE_MAX) {
        FX_LOG(SX_LOG_ERROR,"L2_DMAC_TYPE value is not valid. value:%x\n", key->key.l2_dmac_type);
        is_valid = FALSE;
    }

out:
    return is_valid;
}

static boolean_t is_l3_type_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(l3_type, is_valid, out);

    if (key->key.l3_type > SX_ACL_L3_TYPE_MAX) {
        FX_LOG(SX_LOG_ERROR,"L3_TYPE value is not valid. value:%x\n", key->key.l3_type);
        is_valid = FALSE;
    }

out:
    return is_valid;
}

static boolean_t is_label_id_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    sx_mpls_label_t* label_key = NULL;
    sx_mpls_label_t* label_mask = NULL;

    if (NULL == key) {
        FX_LOG(SX_LOG_ERROR,"key is NULL.\n");
        is_valid = FALSE;
        goto out;
    }

    switch (key->key_id) {
    case FLEX_ACL_KEY_MPLS_LABEL_ID_1:
        label_key = &(key->key.mpls_label_id_1);
        label_mask = &(key->mask.mpls_label_id_1);
        break;

    case FLEX_ACL_KEY_MPLS_LABEL_ID_2:
        label_key = &(key->key.mpls_label_id_2);
        label_mask = &(key->mask.mpls_label_id_2);
        break;

    case FLEX_ACL_KEY_MPLS_LABEL_ID_3:
        label_key = &(key->key.mpls_label_id_3);
        label_mask = &(key->mask.mpls_label_id_3);
        break;

    case FLEX_ACL_KEY_MPLS_LABEL_ID_4:
        label_key = &(key->key.mpls_label_id_4);
        label_mask = &(key->mask.mpls_label_id_4);
        break;

    case FLEX_ACL_KEY_MPLS_LABEL_ID_5:
        label_key = &(key->key.mpls_label_id_5);
        label_mask = &(key->mask.mpls_label_id_5);
        break;

    case FLEX_ACL_KEY_MPLS_LABEL_ID_6:
        label_key = &(key->key.mpls_label_id_6);
        label_mask = &(key->mask.mpls_label_id_6);
        break;

    default:
        FX_LOG(SX_LOG_ERROR,"Key %s is invalid for mpls\n", KEY_ID_2STR(key->key_id));
        is_valid = FALSE;
        goto out;
    }

    if (*label_key > 0xFFFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"label id %u is not valid for key type %s.\n", *label_key, KEY_ID_2STR(key->key_id));
    }

    if (*label_mask > 0xFFFFF) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"label mask 0x%x is not valid for key type %s.\n", *label_mask, KEY_ID_2STR(key->key_id));
    }
out:
    return is_valid;
}

static boolean_t is_mpls_labels_valid_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    if (key->key.mpls_labels_valid > 0x3F) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"mpls labels valid key is not valid.\n");
    }

    if (key->mask.mpls_labels_valid > 0x3F) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"mpls labels valid mask is not valid.\n");
    }

    return is_valid;
}

static boolean_t is_rif_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t             is_valid = TRUE;

    if (key->key_id == FLEX_ACL_KEY_ERIF) {
        BOOLEAN_MASK_CHECK(erif, is_valid, out);
        AVOID_VALIDATION_IF_MASK_FALSE(erif, out);
    } else {
        BOOLEAN_MASK_CHECK(irif, is_valid, out);
        AVOID_VALIDATION_IF_MASK_FALSE(irif, out);
    }

out:
    return is_valid;
}

static boolean_t is_virtual_router_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(virtual_router, is_valid, out);
    AVOID_VALIDATION_IF_MASK_FALSE(virtual_router, out);

out:
    return is_valid;
}


static boolean_t is_tunnel_type_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(tunnel_type, is_valid, out);

    if (key->key.tunnel_type > SX_TUNNEL_TYPE_MAX) {
        FX_LOG(SX_LOG_ERROR,"Invalid tunnel type :%u \n", key->key.tunnel_type);
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_tunnel_nve_type_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(tunnel_nve_type, is_valid, out);

    if ((key->key.tunnel_nve_type > SX_TUNNEL_TYPE_NVE_MAX) || (key->key.tunnel_nve_type < SX_TUNNEL_TYPE_NVE_MIN)) {
        FX_LOG(SX_LOG_ERROR,"Invalid tunnel nve type :%u \n", key->key.tunnel_nve_type);
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_l4_type_extended_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(l4_type_extended, is_valid, out);

    if (key->key.l4_type_extended >= SX_ACL_L4_TYPE_EXTENDED_LAST) {
        FX_LOG(SX_LOG_ERROR,"Invalid l4_ty_extended, type :%u \n", key->key.l4_type_extended);
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_src_port_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t            is_valid = TRUE;

    BOOLEAN_MASK_CHECK(src_port, is_valid, out);
    AVOID_VALIDATION_IF_MASK_FALSE(src_port, out);

    if ((SX_PORT_TYPE_ID_GET(key->key.src_port) & SX_PORT_TYPE_VPORT)) {
        FX_LOG(SX_LOG_ERROR,"ACL : Source port matching on vPort is not allowed.\n");
        is_valid = FALSE;
        goto out;
    }
out:
    return is_valid;
}

static boolean_t is_dst_port_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t            is_valid = TRUE;

    BOOLEAN_MASK_CHECK(dst_port, is_valid, out);
    AVOID_VALIDATION_IF_MASK_FALSE(dst_port, out);

    if ((SX_PORT_TYPE_ID_GET(key->key.dst_port) & SX_PORT_TYPE_VPORT)) {
        FX_LOG(SX_LOG_ERROR,"ACL : Destination port matching on vPort is not allowed.\n");
        is_valid = FALSE;
        goto out;
    }

    if ((SX_PORT_TYPE_ID_GET(key->key.dst_port) == SX_PORT_TYPE_LAG)) {
        FX_LOG(SX_LOG_ERROR,"ACL : Destination port matching on LAG is not allowed.\n");
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_buff_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(buff, is_valid, out);

    if (key->key.buff > 9 /*SX_COS_ING_PG_MAX_E*/) {  //    SX_COS_ING_PG_CTRL_9_E = 9,
        FX_LOG(SX_LOG_ERROR,"BUFF key value is not valid. value:%x\n", key->key.buff);
        is_valid = FALSE;
    }

out:
    return is_valid;
}

static boolean_t is_l4_port_range_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t            is_valid = TRUE;

    BOOLEAN_MASK_CHECK(l4_port_range, is_valid, out);

    if (key->key.l4_port_range.port_range_cnt > RM_API_ACL_PORT_RANGES_MAX) {
        is_valid = FALSE;
        FX_LOG(SX_LOG_ERROR,"Number of port ranges exceeds the maximum. Max is :%d \n", RM_API_ACL_PORT_RANGES_MAX);
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_rx_list_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t                is_valid = TRUE;

    BOOLEAN_MASK_CHECK(rx_list, is_valid, out);

out:
    return is_valid;
}

static boolean_t is_port_list_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t                    is_valid = TRUE;
    sx_mc_container_id_t         mc_container_id;
    sx_acl_port_list_match_t     match_type;

    if (key->key_id == FLEX_ACL_KEY_RX_PORT_LIST) {
        BOOLEAN_MASK_CHECK(rx_port_list, is_valid, out);
        mc_container_id = key->key.rx_port_list.mc_container_id;
        match_type = key->key.rx_port_list.match_type;
    } else { /* FLEX_ACL_KEY_TX_PORT_LIST */
        BOOLEAN_MASK_CHECK(tx_port_list, is_valid, out);
        mc_container_id = key->key.tx_port_list.mc_container_id;
        match_type = key->key.tx_port_list.match_type;
    }
    (void)mc_container_id;

    if ((match_type != SX_ACL_PORT_LIST_MATCH_NEGATIVE) &&
        (match_type != SX_ACL_PORT_LIST_MATCH_POSITIVE)) {
        FX_LOG(SX_LOG_ERROR,"PORT_LIST : Invalid match type:%u.\n", match_type);
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}

static boolean_t is_user_token_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t                 is_valid = TRUE;
    return is_valid;
}

static boolean_t is_discard_state_valid(sx_flex_acl_key_desc_t *key)
{
    boolean_t is_valid = TRUE;

    BOOLEAN_MASK_CHECK(discard_state, is_valid, out);

    if (key->key.discard_state >= SX_ACL_TRAP_FORWARD_ACTION_TYPE_LAST) {
        FX_LOG(SX_LOG_ERROR,"Discard state is invalid\n");
        is_valid = FALSE;
        goto out;
    }

out:
    return is_valid;
}


/* Key value validation. */
sx_status_t acl_keys_validate(sx_flex_acl_flex_rule_t  *rule)
{
    sx_status_t              rc = SX_STATUS_SUCCESS;
    uint32_t                 j;

    /* rules key fields validation */
    for (j = 0; j < rule->key_desc_count; j++) {
        /* Key value validation. */
        if (keys_validation[rule->key_desc_list_p[j].key_id] &&
                (keys_validation[rule->key_desc_list_p[j].key_id](&rule->key_desc_list_p[j]) == FALSE)) {
            FX_LOG(SX_LOG_ERROR,"ACL : Key id %u (%s) value id is not valid.\n",
                    rule->key_desc_list_p[j].key_id,
                    KEY_ID_2STR(rule->key_desc_list_p[j].key_id));
            rc = SX_STATUS_PARAM_ERROR;
        }
        if (rule->key_desc_list_p[j].key_id <= FLEX_ACL_KEY_INVALID ||
            rule->key_desc_list_p[j].key_id >= FLEX_ACL_KEY_LAST) {
            FX_LOG(SX_LOG_ERROR,"ACL : Key id %u value is out of range.\n",
                    rule->key_desc_list_p[j].key_id);
            rc = SX_STATUS_PARAM_ERROR;
        }
    }
    return rc;
}
