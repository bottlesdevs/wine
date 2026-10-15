#include <gio/gio.h>
#include <stdio.h>
#include <string.h>

static FILE *calls;
static gboolean denied;
static gboolean populated;
static GVariant *attributes;
static const char *record;
static char *stored_record;
static gboolean reject_store;
static const char collection_path[] = "/org/freedesktop/secrets/collection/fixture";
static const char item_path[] = "/org/freedesktop/secrets/collection/fixture/item0";
static const char session_path[] = "/org/freedesktop/secrets/session/fixture";
/* Synthetic cache records for account enumeration; never used for a live sign-in. */
static const char valid_record[] =
    "1\nfixture-refresh-not-a-token\ne30.eyJhdWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLC"
    "JvaWQiOiJmaXh0dXJlLWFjY291bnQtaWQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJmaXh0dXJlLXVzZXJAZXhhbXBsZS5pbn"
    "ZhbGlkIiwibmFtZSI6IkZpeHR1cmUgQWNjb3VudCIsInRpZCI6ImZpeHR1cmUtdGVuYW50In0.fixture";
static const char wrong_record[] =
    "1\nfixture-refresh-not-a-token\ne30.eyJhdWQiOiIyMjIyMjIyMi0yMjIyLTIyMjItMjIyMi0yMjIyMjIyMjIyMjIiLC"
    "JvaWQiOiJmaXh0dXJlLWFjY291bnQtaWQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJmaXh0dXJlLXVzZXJAZXhhbXBsZS5pbn"
    "ZhbGlkIiwibmFtZSI6IkZpeHR1cmUgQWNjb3VudCIsInRpZCI6ImZpeHR1cmUtdGVuYW50In0.fixture";
static const char xml[] =
    "<node><interface name='org.freedesktop.Secret.Service'>"
    "<property name='Collections' type='ao' access='read'/>"
    "<method name='SearchItems'><arg type='a{ss}' direction='in'/>"
    "<arg type='ao' direction='out'/><arg type='ao' direction='out'/></method>"
    "<method name='ReadAlias'><arg type='s' direction='in'/><arg type='o' direction='out'/></method>"
    "<method name='OpenSession'><arg type='s' direction='in'/><arg type='v' direction='in'/>"
    "<arg type='v' direction='out'/><arg type='o' direction='out'/></method>"
    "<method name='GetSecrets'><arg type='ao' direction='in'/><arg type='o' direction='in'/>"
    "<arg type='a{o(oayays)}' direction='out'/></method>"
    "<method name='Unlock'><arg type='ao' direction='in'/><arg type='ao' direction='out'/>"
    "<arg type='o' direction='out'/></method></interface>"
    "<interface name='org.freedesktop.Secret.Collection'>"
    "<property name='Items' type='ao' access='read'/><property name='Label' type='s' access='read'/>"
    "<property name='Locked' type='b' access='read'/><property name='Created' type='t' access='read'/><property name='Modified' type='t' access='read'/>"
    "<method name='CreateItem'><arg type='a{sv}' direction='in'/><arg type='(oayays)' direction='in'/><arg type='b' direction='in'/>"
    "<arg type='o' direction='out'/><arg type='o' direction='out'/></method></interface>"
    "<interface name='org.freedesktop.Secret.Item'>"
    "<property name='Locked' type='b' access='read'/><property name='Attributes' type='a{ss}' access='read'/>"
    "<property name='Label' type='s' access='read'/><property name='Created' type='t' access='read'/>"
    "<property name='Modified' type='t' access='read'/>"
    "<method name='GetSecret'><arg type='o' direction='in'/><arg type='(oayays)' direction='out'/></method></interface>"
    "<interface name='org.freedesktop.Secret.Session'><method name='Close'/></interface></node>";

static GVariant *empty_paths(void)
{
    return g_variant_new_objv(NULL, 0);
}

static GVariant *secret_value(void)
{
    return g_variant_new("(o@ay@ays)", session_path,
                         g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, NULL, 0, 1),
                         g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, record, strlen(record), 1), "text/plain");
}

static void create_item(GVariant *parameters, GDBusMethodInvocation *invocation)
{
    GVariant *properties, *secret, *new_attributes, *options, *value;
    const char *session, *content, *client = NULL, *prefix = NULL, *authority = NULL, *expected_prefix = NULL;
    const void *bytes;
    gsize length;
    gboolean replace, matched;
    char *expected;

    g_variant_get(parameters, "(@a{sv}@(oayays)b)", &properties, &secret, &replace);
    g_variant_get(secret, "(&o@ay@ay&s)", &session, &options, &value, &content);
    bytes = g_variant_get_fixed_array(value, &length, 1);
    new_attributes = g_variant_lookup_value(properties, "org.freedesktop.Secret.Item.Attributes", G_VARIANT_TYPE("a{ss}"));
    expected = g_strdup_printf("1\nfixture-next-refresh-not-a-token\n%s", strchr(strchr(valid_record, '\n') + 1, '\n') + 1);
    matched = new_attributes && attributes && replace && !strcmp(session, session_path) &&
              g_variant_lookup(new_attributes, "client", "&s", &client) &&
              g_variant_lookup(new_attributes, "authority", "&s", &authority) &&
              g_variant_lookup(new_attributes, "prefix", "&s", &prefix) &&
              g_variant_lookup(attributes, "prefix", "&s", &expected_prefix) &&
              !strcmp(client, "11111111-1111-1111-1111-111111111111") && !strcmp(authority, "common") &&
              !strcmp(prefix, expected_prefix) && length == strlen(expected) && !memcmp(bytes, expected, length);
    fprintf(calls, "%s\n", matched ? "StoreMatched" : "StoreMismatch");
    fflush(calls);
    if (!matched || reject_store)
        g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.Secret.Error.IsLocked", "Fixture storage rejects this write");
    else
    {
        g_free(stored_record);
        stored_record = g_strndup(bytes, length);
        record = stored_record;
        populated = TRUE;
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(oo)", item_path, "/"));
    }
    g_free(expected);
    if (new_attributes) g_variant_unref(new_attributes);
    g_variant_unref(value);g_variant_unref(options);g_variant_unref(secret);g_variant_unref(properties);
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
        {
            if (attributes) g_variant_unref(attributes);
            g_variant_get(parameters, "(@a{ss})", &attributes);
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(@ao@ao)",
                populated ? g_variant_new_objv((const gchar * const[]){item_path}, 1) : empty_paths(), empty_paths()));
        }
    }
    else if (!strcmp(method, "Unlock"))
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(@aoo)", empty_paths(), "/"));
    else if (!strcmp(method, "ReadAlias"))
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(o)", collection_path));
    else if (!strcmp(method, "CreateItem")) create_item(parameters, invocation);
    else if (!strcmp(method, "OpenSession"))
    {
        const char *algorithm;
        GVariant *input;
        g_variant_get(parameters, "(&sv)", &algorithm, &input);
        if (strcmp(algorithm, "plain"))
            g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.DBus.Error.NotSupported", "Only plain fixture sessions are provided");
        else
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(vo)", g_variant_new_string(""), session_path));
        g_variant_unref(input);
    }
    else if (populated && !strcmp(method, "GetSecret"))
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(@(oayays))", secret_value()));
    else if (populated && !strcmp(method, "GetSecrets"))
    {
        GVariantBuilder values;
        g_variant_builder_init(&values, G_VARIANT_TYPE("a{o(oayays)}"));
        g_variant_builder_add(&values, "{o@(oayays)}", item_path, secret_value());
        g_dbus_method_invocation_return_value(invocation, g_variant_new("(@a{o(oayays)})", g_variant_builder_end(&values)));
    }
    else if (!strcmp(method, "Close")) g_dbus_method_invocation_return_value(invocation, g_variant_new("()"));
    else g_dbus_method_invocation_return_dbus_error(invocation, "org.freedesktop.DBus.Error.NotSupported", "Unexpected fixture method");
}

static GVariant *get_property(GDBusConnection *connection, const gchar *sender, const gchar *path,
                              const gchar *interface, const gchar *property, GError **error, gpointer data)
{
    if (!strcmp(property, "Collections")) return g_variant_new_objv((const gchar * const[]){collection_path}, 1);
    if (!strcmp(property, "Items")) return populated ? g_variant_new_objv((const gchar * const[]){item_path}, 1) : empty_paths();
    if (!strcmp(property, "Locked")) return g_variant_new_boolean(FALSE);
    if (!strcmp(property, "Attributes")) return attributes ? g_variant_ref(attributes) : g_variant_new_array(G_VARIANT_TYPE("{ss}"), NULL, 0);
    if (!strcmp(property, "Label")) return g_variant_new_string("Fixture Account");
    if (!strcmp(property, "Created") || !strcmp(property, "Modified")) return g_variant_new_uint64(1);
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

    if (argc != 4 || (strcmp(argv[3], "empty") && strcmp(argv[3], "denied") && strcmp(argv[3], "record") && strcmp(argv[3], "wrong-audience") && strcmp(argv[3], "store-error") && strcmp(argv[3], "device")) || !(calls = fopen(argv[2], "wb"))) return 1;
    denied = !strcmp(argv[3], "denied");
    populated = !strcmp(argv[3], "record") || !strcmp(argv[3], "wrong-audience") || !strcmp(argv[3], "store-error");
    reject_store = !strcmp(argv[3], "store-error");
    record = !strcmp(argv[3], "wrong-audience") ? wrong_record : valid_record;
    connection = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!connection) goto failed;
    node = g_dbus_node_info_new_for_xml(xml, &error);
    if (!node || !g_dbus_connection_register_object(connection, "/org/freedesktop/secrets", node->interfaces[0], &table, NULL, NULL, &error)) goto failed;
    if (!g_dbus_connection_register_object(connection, item_path, node->interfaces[2], &table, NULL, NULL, &error) ||
        !g_dbus_connection_register_object(connection, session_path, node->interfaces[3], &table, NULL, NULL, &error)) goto failed;
    if (!g_dbus_connection_register_object(connection, collection_path, node->interfaces[1], &table, NULL, NULL, &error)) goto failed;
    if (!g_dbus_connection_register_object(connection, "/org/freedesktop/secrets/aliases/default", node->interfaces[1], &table, NULL, NULL, &error)) goto failed;
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
