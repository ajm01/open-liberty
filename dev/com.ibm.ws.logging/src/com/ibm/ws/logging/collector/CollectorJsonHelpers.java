/*******************************************************************************
 * Copyright (c) 2018, 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.logging.collector;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.text.SimpleDateFormat;
import java.util.ArrayList;

import com.ibm.ws.logging.data.AccessLogData;
import com.ibm.ws.logging.data.AuditData;
import com.ibm.ws.logging.data.FFDCData;
import com.ibm.ws.logging.data.JSONObject;
import com.ibm.ws.logging.data.JSONObject.JSONObjectBuilder;
import com.ibm.ws.logging.data.KeyValuePair;
import com.ibm.ws.logging.data.KeyValuePairList;
import com.ibm.ws.logging.data.LogTraceData;
import com.ibm.ws.logging.data.Pair;

/**
 * CollectorJsonHelpers contains methods shared between CollectorjsonUtils and CollectorJsonUtils1_1
 */
public class CollectorJsonHelpers {


    private static String startMessageJsonFields = null;
    private static String startAccessLogJsonFields = null;
    private static String startTraceJsonFields = null;
    private static String startFFDCJsonFields = null;
    private static String startAuditJsonFields = null;

    private static String startMessageLogstashCollector = null;
    private static String startAccessLogLogstashCollector = null;
    private static String startTraceLogstashCollector = null;
    private static String startFFDCLogstashCollector = null;
    private static String startAuditLogstashCollector = null;
    private static String startGCLogstashCollector = null;

    public static String hostName = null;
    public static String wlpUserDir = null;
    public static String serverName = null;

    private static String startMessageJson = null;
    private static String startMessageJson1_1 = null;
    private static String startTraceJson = null;
    private static String startTraceJson1_1 = null;
    private static String startFFDCJson = null;
    private static String startFFDCJson1_1 = null;
    private static String startAccessLogJson = null;
    private static String startAccessLogJson1_1 = null;
    private static String startBatchJobLogJson = null;
    private static String startBatchJobLogJson1_1 = null;
    private static String startGCJson = null;
    private static String startGCJson1_1 = null;
    private static String startAuditJson = null;
    private static String startAuditJson1_1 = null;
    private static final String TYPE_FIELD_PREPPEND = "\"type\":\"";
    private static final String TYPE_FIELD_APPEND = "\"";
    private static final String MESSAGE_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.MESSAGES_LOG_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String TRACE_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.TRACE_LOG_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String ACCESS_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.ACCESS_LOG_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String BATCHJOB_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.BATCHJOB_LOG_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String FFDC_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.FFDC_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String GC_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.GC_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static final String AUDIT_JSON_TYPE_FIELD = TYPE_FIELD_PREPPEND + CollectorConstants.AUDIT_LOG_EVENT_TYPE + TYPE_FIELD_APPEND;
    private static String unchangingFieldsJson = null;
    private static String unchangingFieldsJson1_1 = null;
    public final static String TRUE_BOOL = "true";
    public final static String FALSE_BOOL = "false";
    public final static String INT_SUFFIX = "_int";
    public final static String FLOAT_SUFFIX = "_float";
    public final static String BOOL_SUFFIX = "_bool";
    public final static String LONG_SUFFIX = "_long";
    public static final String LINE_SEPARATOR;
    public static final String OMIT_FIELDS_STRING = "@@@OMIT@@@";
    private static final int JSON_KEY = CollectorConstants.KEYS_JSON;
    private static final int LOGSTASH_KEY = CollectorConstants.KEYS_LOGSTASH;

    static {
        LINE_SEPARATOR = AccessController.doPrivileged(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return System.getProperty("line.separator");
            }
        });
    }

    public static void setHostName(String host) {
        hostName = host;
    }

    public static void setWlpUserDir(String userDir) {
        wlpUserDir = userDir;
    }

    public static void setServerName(String server) {
        serverName = server;
    }

    protected static String getEventType(String source, String location) {
        if (source.equals(CollectorConstants.GC_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.GC_EVENT_TYPE;
        } else if (source.equals(CollectorConstants.MESSAGES_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.MESSAGES_LOG_EVENT_TYPE;
        } else if (source.endsWith(CollectorConstants.TRACE_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.TRACE_LOG_EVENT_TYPE;
        } else if (source.endsWith(CollectorConstants.FFDC_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.FFDC_EVENT_TYPE;
        } else if (source.endsWith(CollectorConstants.ACCESS_LOG_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.ACCESS_LOG_EVENT_TYPE;
        } else if (source.endsWith(CollectorConstants.BATCHJOB_LOG_SOURCE) && location.equals(CollectorConstants.MEMORY)) {
            return CollectorConstants.BATCHJOB_LOG_EVENT_TYPE;
        } else if (source.contains(CollectorConstants.AUDIT_LOG_SOURCE)) {
            return CollectorConstants.AUDIT_LOG_EVENT_TYPE;
        } else
            return "";
    }

    public static ThreadLocal<BurstDateFormat> dateFormatTL = new ThreadLocal<BurstDateFormat>() {
        @Override
        protected BurstDateFormat initialValue() {
            return new BurstDateFormat(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ"));
        }
    };

    protected static boolean addToJSON(StringBuilder sb, String name, String value, boolean jsonEscapeName,
                                       boolean jsonEscapeValue, boolean trim, boolean isFirstField) {

        boolean b = addToJSON(sb, name, value, jsonEscapeName, jsonEscapeValue, trim, isFirstField, false);
        return b;
    }

    protected static boolean addToJSON(StringBuilder sb, String name, String value, boolean jsonEscapeName,
                                       boolean jsonEscapeValue, boolean trim, boolean isFirstField, boolean isQuoteless) {

        // if name or value is null just return
        if (name == null || value == null)
            return false;

        // if the field name is to be omitted for the event type
        if (name.equals(OMIT_FIELDS_STRING))
            return false;

        // add comma if isFirstField == false
        if (!isFirstField) {
            sb.append(",");
        }

        // trim value if requested
        if (trim)
            value = value.trim();

        sb.append("\"");
        // escape name if requested

        if (jsonEscapeName)
            jsonEscape3(sb, name);
        else
            sb.append(name);

        //If the type of the field is NUMBER, then do not add quotations around the value
        if (isQuoteless) {

            sb.append("\":");

            if (jsonEscapeValue)
                jsonEscape3(sb, value);
            else
                sb.append(value);

        } else {

            sb.append("\":\"");

            // escape value if requested
            if (jsonEscapeValue)
                jsonEscape3(sb, value);
            else
                sb.append(value);

            sb.append("\"");

        }
        return true;
    }

    /**
     * Escape \b, \f, \n, \r, \t, ", \, / characters and appends to a string builder
     *
     * @param sb String builder to append to
     * @param s  String to escape
     */
    protected static void jsonEscape3(StringBuilder sb, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;

                // Fall through because we just need to add \ (escaped) before the character
                case '\\':
                case '\"':
                case '/':
                    sb.append("\\");
                    sb.append(c);
                    break;
                default:
                    sb.append(c);
            }
        }
    }

    public static void updateFieldMappings() {
        //@formatter:off
        JSONObjectBuilder jsonBuilder = new JSONObjectBuilder();

        // We should initialize both the regular JSON logging and LogstashCollector variants
        for (int i = 0; i < 2; i++) {
            // Audit events
            jsonBuilder = new JSONObjectBuilder();
            jsonBuilder.addField(AuditData.getTypeKey(i), CollectorConstants.AUDIT_LOG_EVENT_TYPE, false, false)
                       .addField(AuditData.getHostKey(i), hostName, false, false)
                       .addField(AuditData.getUserDirKey(i), wlpUserDir, false, true)
                       .addField(AuditData.getServerNameKey(i), serverName, false, false);
            if (i == JSON_KEY)
                startAuditJsonFields = jsonBuilder.toString();
            else if (i == LOGSTASH_KEY)
                startAuditLogstashCollector = jsonBuilder.toString();

            // LogTraceData for message events
            jsonBuilder = new JSONObjectBuilder();
            jsonBuilder.addField(LogTraceData.getTypeKey(i, true), CollectorConstants.MESSAGES_LOG_EVENT_TYPE, false, false)
                       .addField(LogTraceData.getHostKey(i, true), hostName, false, false)
                       .addField(LogTraceData.getUserDirKey(i, true), wlpUserDir, false, true)
                       .addField(LogTraceData.getServerNameKey(i, true), serverName, false, false);
            if (i == JSON_KEY)
                startMessageJsonFields = jsonBuilder.toString();
            else if (i == LOGSTASH_KEY)
                startMessageLogstashCollector = jsonBuilder.toString();

            // LogTraceData for trace events
            jsonBuilder = new JSONObjectBuilder();
            jsonBuilder.addField(LogTraceData.getTypeKey(i, false), CollectorConstants.TRACE_LOG_EVENT_TYPE, false, false)
                       .addField(LogTraceData.getHostKey(i, false), hostName, false, false)
                       .addField(LogTraceData.getUserDirKey(i, false), wlpUserDir, false, true)
                       .addField(LogTraceData.getServerNameKey(i, false), serverName, false, false);
            if (i == JSON_KEY)
                startTraceJsonFields = jsonBuilder.toString();
            else if (i == LOGSTASH_KEY)
                startTraceLogstashCollector = jsonBuilder.toString();

            // Access Log events
            jsonBuilder = new JSONObjectBuilder();
            jsonBuilder.addField(AccessLogData.getTypeKey(i), CollectorConstants.ACCESS_LOG_EVENT_TYPE, false, false)
                       .addField(AccessLogData.getHostKey(i), hostName, false, false)
                       .addField(AccessLogData.getUserDirKey(i), wlpUserDir, false, true)
                       .addField(AccessLogData.getServerNameKey(i), serverName, false, false);
            if (i == JSON_KEY)
                startAccessLogJsonFields = jsonBuilder.toString();
            else if (i == LOGSTASH_KEY)
                startAccessLogLogstashCollector = jsonBuilder.toString();

            // FFDC events
            jsonBuilder = new JSONObjectBuilder();
            jsonBuilder.addField(FFDCData.getTypeKey(i), CollectorConstants.FFDC_EVENT_TYPE, false, false)
                       .addField(FFDCData.getHostKey(i), hostName, false, false)
                       .addField(FFDCData.getUserDirKey(i), wlpUserDir, false, true)
                       .addField(FFDCData.getServerNameKey(i), serverName, false, false);
            if (i == JSON_KEY)
                startFFDCJsonFields = jsonBuilder.toString();
            else if (i == LOGSTASH_KEY)
                startFFDCLogstashCollector = jsonBuilder.toString();
        }

        // GC events are only in Logstash Collector, so we only need to initialize one variant of it
        jsonBuilder = new JSONObjectBuilder();
        jsonBuilder.addField("type", CollectorConstants.GC_EVENT_TYPE, false, false)
                   .addField("hostName", hostName, false, false)
                   .addField("wlpUserDir", wlpUserDir, false, true)
                   .addField("serverName", serverName, false, false);
        startGCLogstashCollector = jsonBuilder.toString();
        //formatter:on
    }

    protected static JSONObjectBuilder startGC() {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        jsonBuilder.addPreformatted(startGCLogstashCollector);
        return jsonBuilder;
    }

    protected static JSONObjectBuilder startAudit(int format) {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        // We're assuming startAuditJsonFields will never be null - i.e. updateFieldMappings is always called before this method is called
        if (format == JSON_KEY)
            jsonBuilder.addPreformatted(startAuditJsonFields);
        else if (format == LOGSTASH_KEY)
            jsonBuilder.addPreformatted(startAuditLogstashCollector);
        return jsonBuilder;
    }

    protected static JSONObjectBuilder startMessage(int format) {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        // We're assuming startMessageJsonFields will never be null - i.e. updateFieldMappings is always called before this method is called
        if (format == JSON_KEY)
            jsonBuilder.addPreformatted(startMessageJsonFields);
        else if (format == LOGSTASH_KEY)
            jsonBuilder.addPreformatted(startMessageLogstashCollector);
        return jsonBuilder;
    }

    protected static JSONObjectBuilder startTrace(int format) {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        // We're assuming startTraceJsonFields will never be null - i.e. updateFieldMappings is always called before this method is called
        if (format == JSON_KEY)
            jsonBuilder.addPreformatted(startTraceJsonFields);
        else if (format == LOGSTASH_KEY)
            jsonBuilder.addPreformatted(startTraceLogstashCollector);
        return jsonBuilder;
    }

<<<<<<< HEAD
    protected static JSONObjectBuilder startFFDC(int format) {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        // We're assuming startFFDCJsonFields will never be null - i.e. updateFieldMappings is always called before this method is called
        if (format == JSON_KEY)
            jsonBuilder.addPreformatted(startFFDCJsonFields);
        else if (format == LOGSTASH_KEY)
            jsonBuilder.addPreformatted(startFFDCLogstashCollector);
        return jsonBuilder;
    }

    protected static JSONObjectBuilder startAccessLog(int format) {
        JSONObjectBuilder jsonBuilder = new JSONObject.JSONObjectBuilder();
        // We're assuming startAccessLogJsonFields and startAccessLogLogstashCollector will never be null - i.e. updateFieldMappings is always called before this method is called
        if (format == JSON_KEY)
            jsonBuilder.addPreformatted(startAccessLogJsonFields);
        else if (format == LOGSTASH_KEY)
            jsonBuilder.addPreformatted(startAccessLogLogstashCollector);
        return jsonBuilder;
=======
    protected static StringBuilder startBatchJobLogJson(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(2048);

        if (startBatchJobLogJson != null) {
            sb.append(startBatchJobLogJson);
        } else {
            sb.append("{");
            sb.append(BATCHJOB_JSON_TYPE_FIELD);
            addUnchangingFields(sb, hostName, wlpUserDir, serverName);

            startBatchJobLogJson = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startGCJson(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startGCJson != null) {
            sb.append(startGCJson);
        } else {
            sb.append("{");
            sb.append(GC_JSON_TYPE_FIELD);
            addUnchangingFields(sb, hostName, wlpUserDir, serverName);

            startGCJson = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startAuditJson(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(2048);

        if (startAuditJson != null) {
            sb.append(startAuditJson);
        } else {
            sb.append("{");
            sb.append(AUDIT_JSON_TYPE_FIELD);
            addUnchangingFields(sb, hostName, wlpUserDir, serverName);
            startAuditJson = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startAuditJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(2048);

        if (startAuditJson1_1 != null) {
            sb.append(startAuditJson1_1);
        } else {
            sb.append("{");
            sb.append(AUDIT_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);
            startAuditJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startMessageJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startMessageJson1_1 != null) {
            sb.append(startMessageJson1_1);
        } else {
            sb.append("{");
            sb.append(MESSAGE_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startMessageJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startTraceJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startTraceJson1_1 != null) {
            sb.append(startTraceJson1_1);
        } else {
            sb.append("{");
            sb.append(TRACE_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startTraceJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startFFDCJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startFFDCJson1_1 != null) {
            sb.append(startFFDCJson1_1);
        } else {
            sb.append("{");
            sb.append(FFDC_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startFFDCJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startAccessLogJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startAccessLogJson1_1 != null) {
            sb.append(startAccessLogJson1_1);
        } else {
            sb.append("{");
            sb.append(ACCESS_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startAccessLogJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startBatchJobLogJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startBatchJobLogJson1_1 != null) {
            sb.append(startBatchJobLogJson1_1);
        } else {
            sb.append("{");
            sb.append(BATCHJOB_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startBatchJobLogJson1_1 = sb.toString();
        }

        return sb;
    }

    protected static StringBuilder startGCJson1_1(String hostName, String wlpUserDir, String serverName) {
        StringBuilder sb = new StringBuilder(512);

        if (startGCJson1_1 != null) {
            sb.append(startGCJson1_1);
        } else {
            sb.append("{");
            sb.append(GC_JSON_TYPE_FIELD);
            addUnchangingFields1_1(sb, hostName, wlpUserDir, serverName);

            startGCJson1_1 = sb.toString();
        }

        return sb;
>>>>>>> (Rebased)
    }

    protected static String formatMessage(String message, int maxLength) {
        return (message.length() > maxLength && maxLength > 0) ? message.substring(0, maxLength) + "..." : message;
    }

    protected static String removeIBMTag(String s) {
        s = s.replace(LogFieldConstants.IBM_TAG, "");
        return s;
    }

    protected static StringBuilder addTagNameForVersion(StringBuilder sb) {

        sb.append(",\"tags\":");

        return sb;
    }

    protected static String jsonifyTags(String[] tags) {
        StringBuilder sb = new StringBuilder(64);

        sb.append("[");
        for (int i = 0; i < tags.length; i++) {

            tags[i] = tags[i].trim();
            if (tags[i].contains(" ") || tags[i].contains("-")) {
                continue;
            }
            sb.append("\"");
            jsonEscape3(sb, tags[i]);
            sb.append("\"");
            if (i != tags.length - 1) {
                sb.append(",");
            }
        }

        //Check if have extra comma due to last tag being dropped for
        if (sb.toString().lastIndexOf(",") == sb.toString().length() - 1) {
            sb.delete(sb.toString().lastIndexOf(","), sb.toString().lastIndexOf(",") + 1);
        }
        sb.append("]");
        return sb.toString();
    }

    protected static String jsonRemoveSpace(String s) {
        StringBuilder sb = new StringBuilder();
        boolean isLine = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n') {
                sb.append(c);
                isLine = true;
            } else if (c == ' ' && isLine) {
            } else if (isLine && c != ' ') {
                isLine = false;
                sb.append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    protected static String getLogLevel(ArrayList<Pair> pairs) {
        KeyValuePair kvp = null;
        String loglevel = null;
        for (Pair p : pairs) {
            if (p instanceof KeyValuePair) {
                kvp = (KeyValuePair) p;
                if (kvp.getKey().equals(LogFieldConstants.LOGLEVEL)) {
                    loglevel = kvp.getStringValue();
                    break;
                }
            }
        }
        return loglevel;
    }

    public static void handleExtensions(KeyValuePairList extensions, String extKey, String extValue) {
        extKey = LogFieldConstants.EXT_PREFIX + extKey;
        if (extKey.indexOf('_', 4) != -1) {
            if (extKey.endsWith(CollectorJsonHelpers.INT_SUFFIX)) {
                try {
                    extensions.addKeyValuePair(extKey, Integer.parseInt(extValue));
                } catch (NumberFormatException e) {
                }
            } else if (extKey.endsWith(CollectorJsonHelpers.FLOAT_SUFFIX)) {
                try {
                    extensions.addKeyValuePair(extKey, Float.parseFloat(extValue));
                } catch (NumberFormatException e) {
                }
            } else if (extKey.endsWith(CollectorJsonHelpers.BOOL_SUFFIX)) {
                if (extValue.toLowerCase().trim().equals(TRUE_BOOL)) {
                    extensions.addKeyValuePair(extKey, true);
                } else if (extValue.toLowerCase().trim().equals(FALSE_BOOL)) {
                    extensions.addKeyValuePair(extKey, false);
                }
            } else if (extKey.endsWith(CollectorJsonHelpers.LONG_SUFFIX)) {
                try {
                    extensions.addKeyValuePair(extKey, Long.parseLong(extValue));
                } catch (NumberFormatException e) {
                }
            } else {
                extensions.addKeyValuePair(extKey, extValue);
            }
        } else {
            extensions.addKeyValuePair(extKey, extValue);
        }
    }
}