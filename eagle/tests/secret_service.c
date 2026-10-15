#include <gio/gio.h>
#include <stdio.h>
#include <string.h>

static FILE *calls;
static gboolean denied;
static const char xml[] =
    "<node><interface name='org.freedesktop.Secret.Service'>"
    "<property name='Collections' type='ao' access='read'/>"
    "<method name='SearchItems'><arg type='a{ss}' direction='in'/>"
    "<arg type='ao' direction='out'/><arg type='ao' direction='out'/></method>"
    "<method name='Unlock'><arg type='ao' direction='in'/><arg type='ao' direction='out'/>"
    "<arg type='o' direction='out'/></method></interface></node>";

static GVariant *empty_paths(void)
{
    return g_variant_new_objv(NULL, 0);
}

static void method_call(GDBusConnection *connection, const gchar *sender, const gchar *path,
                        const gchar *interface, const gchar *method, GVariant *parameters,
                        GDBusMethodInvocation *invocation, gpointer data)
{
    fprintf(calls, "%s\n", method);
    fflush(calls);
    if (!strcmp(method, "SearchItems"))
    {
        if (denied)
            g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.Secret.Error.IsLocked", "The fixture refuses this search");
        else
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(@ao@ao)", empty_paths(), empty_paths()));
    }
    else if (!strcmp(method, "Unlock"))
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(@aoo)", empty_paths(), "/"));
    else g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.DBus.Error.NotSupported", "Unexpected fixture method");
}

static GVariant *get_property(GDBusConnection *connection, const gchar *sender, const gchar *path,
                              const gchar *interface, const gchar *property, GError **error, gpointer data)
{
    if (!strcmp(property, "Collections")) return empty_paths();
    return NULL;
}

int main(int argc, char **argv)
{
    GError *error = NULL;
    GDBusConnection *connection;
    GDBusNodeInfo *node;
    GVariant *reply;
    guint result;
    FILE *ready;
    static const GDBusInterfaceVTable table = {method_call, get_property, NULL, {0}};

    if (argc != 4 || (strcmp(argv[3], "empty") && strcmp(argv[3], "denied")) || !(calls = fopen(argv[2], "wb"))) return 1;
    denied = !strcmp(argv[3], "denied");
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!connection) goto failed;
    node = g_dbus_node_info_new_for_xml(xml, &error);
    if (!node || !g_dbus_connection_register_object(connection, "/org/freedesktop/secrets", node->interfaces[0], &table, NULL, NULL, &error)) goto failed;
    reply = g_dbus_connection_call_sync(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                       "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", "org.freedesktop.secrets", 4),
                                       G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
    if (!reply) goto failed;
    g_variant_get(reply, "(u)", &result);
    g_variant_unref(reply);
    if (result != 1 || !(ready = fopen(argv[1], "wb"))) return 2;
    fputs("ready\n", ready);
    fclose(ready);
    g_main_loop_run(g_main_loop_new(NULL, FALSE));
    return 0;
failed:
    fprintf(stderr, "%s\n", error ? error->message : "fixture initialization failed");
    return 3;
}
