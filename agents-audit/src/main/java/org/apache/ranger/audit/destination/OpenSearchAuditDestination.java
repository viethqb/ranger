//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.apache.ranger.audit.destination;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.ranger.audit.model.AuditEventBase;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.authorization.credutils.CredentialsProviderUtil;
import org.apache.ranger.authorization.credutils.kerberos.KerberosCredentialsProvider;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch.core.BulkRequest;
import org.opensearch.client.opensearch.core.BulkResponse;
import org.opensearch.client.opensearch.core.bulk.BulkResponseItem;
import org.opensearch.client.opensearch.core.bulk.IndexOperation;
import org.opensearch.client.opensearch.indices.OpenRequest;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.rest_client.RestClientTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import java.io.File;
import java.security.PrivilegedActionException;
import java.util.*;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class OpenSearchAuditDestination extends AuditDestination {
    public static final String CONFIG_URLS = "urls";
    public static final String CONFIG_PORT = "port";
    public static final String CONFIG_USER = "user";
    public static final String CONFIG_PWRD = "password";
    public static final String CONFIG_PROTOCOL = "protocol";
    public static final String CONFIG_INDEX = "index";
    public static final String CONFIG_PREFIX = "ranger.audit.opensearch";
    public static final String DEFAULT_INDEX = "ranger_audits";
    private static final Logger LOG = LoggerFactory.getLogger(OpenSearchAuditDestination.class);
    private final AtomicLong lastLoggedAt = new AtomicLong(0L);
    private String index = "index";
    private volatile OpenSearchClient client = null;
    private String protocol;
    private String user;
    private int port;
    private String password;
    private String hosts;
    private Subject subject;

    public OpenSearchAuditDestination() {
        this.propPrefix = "ranger.audit.opensearch";
    }

    public static RestClientBuilder getRestClientBuilder(String urls, String protocol, String user, String password, int port) {
        RestClientBuilder restClientBuilder = RestClient.builder((HttpHost[])MiscUtil.toArray(urls, ",").stream().map((x) -> new HttpHost(x, port, protocol)).toArray((i) -> new HttpHost[i]));
        ThreadFactory clientThreadFactory = (new ThreadFactoryBuilder()).setNameFormat("OpenSearch rest client %s").setDaemon(true).build();
        if (StringUtils.isNotBlank(user) && StringUtils.isNotBlank(password) && !user.equalsIgnoreCase("NONE") && !password.equalsIgnoreCase("NONE")) {
            if (password.contains("keytab") && (new File(password)).exists()) {
                KerberosCredentialsProvider credentialsProvider = CredentialsProviderUtil.getKerberosCredentials(user, password);
                Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create().register("Negotiate", new SPNegoSchemeFactory()).build();
                restClientBuilder.setHttpClientConfigCallback((clientBuilder) -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    clientBuilder.setDefaultAuthSchemeRegistry(authSchemeRegistry);
                    return clientBuilder;
                });
            } else {
                final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(user, password));
                restClientBuilder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    }
                });
                restClientBuilder.setHttpClientConfigCallback((clientBuilder) -> {
                    clientBuilder.setThreadFactory(clientThreadFactory);
                    clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                    return clientBuilder;
                });
            }
        } else {
            LOG.error("OpenSearch Credentials not provided!!");
            CredentialsProvider credentialsProvider = null;
            restClientBuilder.setHttpClientConfigCallback((clientBuilder) -> {
                clientBuilder.setThreadFactory(clientThreadFactory);
                clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                return clientBuilder;
            });
        }

        return restClientBuilder;
    }

    public void init(Properties props, String propPrefix) {
        super.init(props, propPrefix);
        this.protocol = this.getStringProperty(props, propPrefix + "." + "protocol", "http");
        this.user = this.getStringProperty(props, propPrefix + "." + "user", "");
        this.password = this.getStringProperty(props, propPrefix + "." + "password", "");
        this.port = MiscUtil.getIntProperty(props, propPrefix + "." + "port", 9200);
        this.index = this.getStringProperty(props, propPrefix + "." + "index", "ranger_audits");
        this.hosts = this.getHosts();
        LOG.info("Connecting to OpenSearch: " + this.connectionString());
        this.getClient();
    }

    private String connectionString() {
        return String.format(Locale.ROOT, "User:%s, %s://%s:%s/%s", this.user, this.protocol, this.hosts, this.port, this.index);
    }

    public void stop() {
        super.stop();
        this.logStatus();
    }

    public boolean log(Collection<AuditEventBase> events) {
        boolean ret = false;

        try {
            this.logStatusIfRequired();
            this.addTotalCount(events.size());
            OpenSearchClient client = this.getClient();
            if (null == client) {
                this.addDeferredCount(events.size());
                return ret;
            }

            ArrayList<AuditEventBase> eventList = new ArrayList(events);
            BulkRequest.Builder br = new BulkRequest.Builder();

            try {
                for(AuditEventBase event : eventList) {
                    AuthzAuditEvent authzEvent = (AuthzAuditEvent)event;
                    String id = authzEvent.getEventId();
                    Map<String, Object> doc = this.toDoc(authzEvent);
                    br.operations((op) -> op.index((idx) -> ((IndexOperation.Builder)((IndexOperation.Builder)idx.index(this.index)).id(id)).document(doc)));
                }
            } catch (Exception ex) {
                this.addFailedCount(eventList.size());
                this.logFailedEvent(eventList, ex);
            }

            BulkResponse response = client.bulk(br.build());
            if (response.errors()) {
                this.addFailedCount(eventList.size());
                StringBuilder err = new StringBuilder();

                for(BulkResponseItem item : response.items()) {
                    if (item.error() != null) {
                        err.append(item.error().reason());
                    }
                }

                this.logFailedEvent(eventList, "HTTP " + err);
            } else {
                List<BulkResponseItem> items = response.items();

                for(int i = 0; i < items.size(); ++i) {
                    AuditEventBase itemRequest = (AuditEventBase)eventList.get(i);
                    BulkResponseItem itemResponse = (BulkResponseItem)items.get(i);
                    if (itemResponse.error() != null) {
                        this.addFailedCount(1);
                        this.logFailedEvent(Arrays.asList(itemRequest), itemResponse.error().reason());
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(String.format("Indexed %s", itemRequest.getEventKey()));
                        }

                        this.addSuccessCount(1);
                        ret = true;
                    }
                }
            }
        } catch (Throwable t) {
            this.addDeferredCount(events.size());
            this.logError("Error sending message to OpenSearch", t);
        }

        return ret;
    }

    public void flush() {
    }

    public boolean isAsync() {
        return true;
    }

    synchronized OpenSearchClient getClient() {
        if (this.client == null) {
            synchronized(OpenSearchAuditDestination.class) {
                if (this.client == null) {
                    this.client = this.newClient();
                }
            }
        }

        if (this.subject != null) {
            KerberosTicket ticket = CredentialsProviderUtil.getTGT(this.subject);

            try {
                if ((new Date()).getTime() > ticket.getEndTime().getTime()) {
                    this.client = null;
                    CredentialsProviderUtil.ticketExpireTime80 = 0L;
                    this.newClient();
                } else if (CredentialsProviderUtil.ticketWillExpire(ticket)) {
                    this.subject = CredentialsProviderUtil.login(this.user, this.password);
                }
            } catch (PrivilegedActionException e) {
                LOG.error("PrivilegedActionException:", e);
                throw new RuntimeException(e);
            }
        }

        return this.client;
    }

    private OpenSearchClient newClient() {
        try {
            if (StringUtils.isNotBlank(this.user) && StringUtils.isNotBlank(this.password) && this.password.contains("keytab") && (new File(this.password)).exists()) {
                this.subject = CredentialsProviderUtil.login(this.user, this.password);
            }

            RestClientBuilder restClientBuilder = getRestClientBuilder(this.hosts, this.protocol, this.user, this.password, this.port);
            OpenSearchTransport transport = new RestClientTransport(restClientBuilder.build(), new JacksonJsonpMapper());
            OpenSearchClient esClient = new OpenSearchClient(transport);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Initialized client");
            }

            boolean exits = false;

            try {
                exits = esClient.indices().open((new OpenRequest.Builder()).index(this.index, new String[0]).build()).shardsAcknowledged();
            } catch (Exception var6) {
                LOG.warn("Error validating index " + this.index);
            }

            if (exits) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Index exists");
                }
            } else {
                LOG.info("Index does not exist");
            }

            return esClient;
        } catch (Throwable t) {
            this.lastLoggedAt.updateAndGet((lastLoggedAt) -> {
                long now = System.currentTimeMillis();
                long elapsed = now - lastLoggedAt;
                if (elapsed > TimeUnit.MINUTES.toMillis(1L)) {
                    LOG.error("Can't connect to OpenSearch server: " + this.connectionString(), t);
                    return now;
                } else {
                    return lastLoggedAt;
                }
            });
            return null;
        }
    }

    private String getHosts() {
        String urls = MiscUtil.getStringProperty(this.props, this.propPrefix + "." + "urls");
        if (urls != null) {
            urls = urls.trim();
        }

        if ("NONE".equalsIgnoreCase(urls)) {
            urls = null;
        }

        return urls;
    }

    private String getStringProperty(Properties props, String propName, String defaultValue) {
        String value = MiscUtil.getStringProperty(props, propName);
        return null == value ? defaultValue : value;
    }

    Map<String, Object> toDoc(AuthzAuditEvent auditEvent) {
        Map<String, Object> doc = new HashMap();
        doc.put("id", auditEvent.getEventId());
        doc.put("access", auditEvent.getAccessType());
        doc.put("enforcer", auditEvent.getAclEnforcer());
        doc.put("agent", auditEvent.getAgentId());
        doc.put("repo", auditEvent.getRepositoryName());
        doc.put("sess", auditEvent.getSessionId());
        doc.put("reqUser", auditEvent.getUser());
        doc.put("reqData", auditEvent.getRequestData());
        doc.put("resource", auditEvent.getResourcePath());
        doc.put("cliIP", auditEvent.getClientIP());
        doc.put("logType", auditEvent.getLogType());
        doc.put("result", auditEvent.getAccessResult());
        doc.put("policy", auditEvent.getPolicyId());
        doc.put("repoType", auditEvent.getRepositoryType());
        doc.put("resType", auditEvent.getResourceType());
        doc.put("reason", auditEvent.getResultReason());
        doc.put("action", auditEvent.getAction());
        doc.put("evtTime", auditEvent.getEventTime());
        doc.put("seq_num", auditEvent.getSeqNum());
        doc.put("event_count", auditEvent.getEventCount());
        doc.put("event_dur_ms", auditEvent.getEventDurationMS());
        doc.put("tags", auditEvent.getTags());
        doc.put("cluster", auditEvent.getClusterName());
        doc.put("zoneName", auditEvent.getZoneName());
        doc.put("agentHost", auditEvent.getAgentHostname());
        doc.put("policyVersion", auditEvent.getPolicyVersion());
        return doc;
    }
}
