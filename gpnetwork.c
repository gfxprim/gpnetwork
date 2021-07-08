//SPDX-License-Identifier: LGPL-2.0-or-later

/*

    Copyright (C) 2007-2021 Cyril Hrubis <metan@ucw.cz>

 */

#include <net/if.h>
#include <netlink/genl/genl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <utils/gp_list.h>
#include <utils/gp_vec.h>
#include <widgets/gp_widgets.h>

struct iface_info {
	int index;

	gp_dlist_head list_head;

	gp_widget *layout;

	gp_widget *link_addr;
	gp_widget *link_brd;
	gp_widget *mtu;
	gp_widget *flags;

	gp_widget *ipv4;
	gp_widget *ipv6;
};

static gp_dlist iface_list;

static gp_widget *iface_tabs;

static struct iface_info *new_iface_info(int index)
{
	struct iface_info *new;
	gp_htable *uids;

	new = malloc(sizeof(struct iface_info));
	if (!new)
		return NULL;

	gp_dlist_push_tail(&iface_list, &new->list_head);

	new->index = index;
	new->layout = gp_app_layout_fragment_load("gpnetwork", "tab", &uids);

	new->link_addr = gp_widget_by_uid(uids, "link_addr", GP_WIDGET_LABEL);
	new->link_brd = gp_widget_by_uid(uids, "link_brd", GP_WIDGET_LABEL);
	new->mtu = gp_widget_by_uid(uids, "mtu", GP_WIDGET_LABEL);
	new->flags = gp_widget_by_uid(uids, "flags", GP_WIDGET_LABEL);
	new->ipv4 = gp_widget_by_uid(uids, "ipv4", GP_WIDGET_GRID);
	new->ipv6 = gp_widget_by_uid(uids, "ipv6", GP_WIDGET_GRID);

	gp_htable_free(uids);

	return new;
}

static struct iface_info *iface_info_by_index(int index)
{
	gp_dlist_head *i;

	GP_LIST_FOREACH(&iface_list, i) {
		struct iface_info *info = GP_LIST_ENTRY(i, struct iface_info, list_head);

		if (info->index == index)
			return info;
	}

	return NULL;
}

static int iface_info_ipv4_row_by_addr(struct iface_info *info,
                                       struct in_addr *addr,
                                       unsigned char prefixlen)
{
	unsigned int row;
	char buf[INET_ADDRSTRLEN+12];
	size_t len;

	inet_ntop(AF_INET, addr, buf, sizeof(buf));

	len = strlen(buf);

	snprintf(buf + len, sizeof(buf) - len, "/%u", prefixlen);

	for (row = 0; row < info->ipv4->grid->rows; row++) {
		gp_widget *label = gp_widget_grid_get(info->ipv4, 0, row);

		if (!label)
			continue;

		if (!strcmp(label->label->text, buf))
			return row;
	}

	return -1;
}

static void iface_info_del_ipv4_addr(struct iface_info *info, struct in_addr *addr,
                                     unsigned char prefixlen)
{
	int row = iface_info_ipv4_row_by_addr(info, addr, prefixlen);

	if (row < 0) {
		GP_WARN("Attempting to remove nonexistent address");
		return;
	}

	gp_widget_grid_row_del(info->ipv4, row);
}

static void iface_info_new_ipv4_addr(struct iface_info *info, struct in_addr *addr,
                                     unsigned char prefixlen)
{
	unsigned int row = gp_widget_grid_row_append(info->ipv4);

	gp_widget *l = gp_widget_label_printf_new(GP_TATTR_MONO, "%s/%u", inet_ntoa(*addr), prefixlen);

	gp_widget_grid_put(info->ipv4, 0, row, l);
}

static void iface_info_new_ipv6_addr(struct iface_info *info, struct in6_addr *addr,
                                     unsigned char prefixlen)
{
	unsigned int row = gp_widget_grid_row_append(info->ipv6);
	char buf[INET6_ADDRSTRLEN];
	gp_widget *a;


	a = gp_widget_label_printf_new(GP_TATTR_MONO, "%s/%u",
	                               inet_ntop(AF_INET6, addr, buf, sizeof(buf)),
	                               prefixlen);

	gp_widget_grid_put(info->ipv6, 0, row, a);
}

static void rem_iface_info(struct iface_info *info)
{
	if (!info)
		return;

	int idx = gp_widget_tabs_tab_by_child(iface_tabs, info->layout);
	if (idx > 0)
		gp_widget_tabs_tab_del(iface_tabs, idx);

	gp_dlist_rem(&iface_list, &info->list_head);

	free(info);
}

static void set_link_addr(gp_widget *widget, const unsigned char *addr)
{
	if (!widget)
		return;

	gp_widget_label_printf(widget, "%02x:%02x:%02x:%02x:%02x:%02x",
	                       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void set_flags(struct iface_info *info, unsigned int flags)
{
	if (!info->flags)
		return;

	if (flags & IFF_UP)
		gp_widget_label_set(info->flags, "<UP");
	else
		gp_widget_label_set(info->flags, "<DOWN");

	if (flags & IFF_LOOPBACK)
		gp_widget_label_append(info->flags, ",LOOPBACK");

	if (flags & IFF_PROMISC)
		gp_widget_label_append(info->flags, ",PROMISC");

	if (flags & IFF_BROADCAST)
		gp_widget_label_append(info->flags, ",BROADCAST");

	if (flags & IFF_MULTICAST)
		gp_widget_label_append(info->flags, ",MULTICAST");

	gp_widget_label_append(info->flags, ">");
}

static void parse_newlink(struct nlmsghdr *nlh)
{
	struct rtattr *rta;
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);
	int len = IFLA_PAYLOAD(nlh);
	const unsigned char *link_addr = NULL;
	const unsigned char *link_brd = NULL;
	const char *if_name = NULL;
	unsigned int *mtu = NULL;

	printf("---- RMT_NEWLINK ----\n");

	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
		case IFLA_IFNAME:
			if_name = RTA_DATA(rta);
		break;
		case IFLA_ADDRESS:
			if (!(ifi->ifi_flags & IFF_NOARP))
				link_addr = RTA_DATA(rta);
		break;
		case IFLA_BROADCAST:
			if (!(ifi->ifi_flags & IFF_NOARP))
				link_brd = RTA_DATA(rta);
		break;
		case IFLA_MTU:
			mtu = RTA_DATA(rta);
		break;
		default:
			printf("RTA_TYPE=%i\n", rta->rta_type);
		}
	}

	struct iface_info *info = iface_info_by_index(ifi->ifi_index);

	if (!info) {
		if (!if_name)
			return;

		info = new_iface_info(ifi->ifi_index);
		if (!info)
			return;

		gp_widget_tabs_tab_append(iface_tabs, if_name, info->layout);
	}

	set_flags(info, ifi->ifi_flags);

	if (link_addr)
		set_link_addr(info->link_addr, link_addr);

	if (link_brd)
		set_link_addr(info->link_brd, link_brd);

	if (mtu && info->mtu)
		gp_widget_label_printf(info->mtu, "%u", *mtu);

	printf("---------------------\n");
}

static void parse_dellink(struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nlh);

	printf("---- RMT_DELLINK ----\n");

	rem_iface_info(iface_info_by_index(ifi->ifi_index));

	printf("---------------------\n");
}

static void parse_new_del_addr(struct nlmsghdr *nlh, int del)
{
	struct rtattr *rta;
	struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
	int len = IFA_PAYLOAD(nlh);
	struct iface_info *iface_info;
	struct in_addr *addr4 = NULL;
	struct in6_addr *addr6 = NULL;

	if (del)
		printf("---- RTM_DELADDR ----\n");
	else
		printf("---- RTM_NEWADDR ----\n");

	iface_info = iface_info_by_index(ifa->ifa_index);

	for (rta = IFA_RTA(ifa); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch (rta->rta_type) {
		case IFA_ADDRESS:
			switch (ifa->ifa_family) {
			case AF_INET:
				addr4 = RTA_DATA(rta);
			break;
			case AF_INET6:
				addr6 = RTA_DATA(rta);
			break;
			}
		break;
		default:
			printf("RTA_TYPE=%i\n", rta->rta_type);
		}
	}

	if (addr4) {
		if (del)
			iface_info_del_ipv4_addr(iface_info, addr4, ifa->ifa_prefixlen);
		else
			iface_info_new_ipv4_addr(iface_info, addr4, ifa->ifa_prefixlen);
	}

	if (addr6) {
		if (del)
			printf("DEL\n");
		else
			iface_info_new_ipv6_addr(iface_info, addr6, ifa->ifa_prefixlen);
	}

	printf("---------------------\n");
}

static int parse_netlink_msg(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);

	switch (nlh->nlmsg_type) {
	case RTM_DELADDR:
		parse_new_del_addr(nlh, 1);
	break;
	case RTM_DELLINK:
		parse_dellink(nlh);
	break;
	case RTM_NEWLINK:
		parse_newlink(nlh);
	break;
	case RTM_NEWADDR:
		parse_new_del_addr(nlh, 0);
	break;
	case RTM_NEWROUTE:
		printf("New route %u\n", nlh->nlmsg_flags);
	break;
	case RTM_DELROUTE:
		printf("Del route %u\n", nlh->nlmsg_flags);
	break;
	}

	return NL_OK;
}

static int netlink_callback(struct gp_fd *self, struct pollfd *pfd)
{
	(void)pfd;

	nl_recvmsgs_default(self->priv);

	return 0;
}

int main(int argc, char *argv[])
{
	struct nl_sock *socket = nl_socket_alloc();
	gp_widget *layout = gp_widget_grid_new(1, 1, 0);

	iface_tabs = gp_widget_tabs_new(0, 0, NULL, 0);

	gp_widget_grid_put(layout, 0, 0, iface_tabs);

	nl_socket_disable_seq_check(socket);
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, parse_netlink_msg, NULL);

	nl_connect(socket, NETLINK_ROUTE);
	nl_socket_add_memberships(socket, RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE, 0);

	struct rtgenmsg rt_hdr = { .rtgen_family = AF_PACKET };

	int ret = nl_send_simple(socket, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
	nl_recvmsgs_default(socket);

	ret = nl_send_simple(socket, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
	nl_recvmsgs_default(socket);

	gp_fds_add(gp_widgets_fds, nl_socket_get_fd(socket), POLLIN, netlink_callback, socket);

	if (!layout) {
		fprintf(stderr, "Failed to load layout!\n");
		return 1;
	}

	gp_widgets_main_loop(layout, "network", NULL, argc, argv);

	return 0;
}
