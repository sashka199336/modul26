package com.globus.modul26.util;

import java.util.Map;

public class CefUtil {
    public static String toCef(String signatureId, String name, int severity, Map<String, String> extension) {
        StringBuilder cef = new StringBuilder();
        cef.append("CEF:0|YourCompany|modul26|1.0|")
                .append(signatureId).append("|")
                .append(name).append("|")
                .append(severity).append("|");

        extension.forEach((k, v) -> cef.append(k).append("=").append(v).append(" "));
        return cef.toString().trim();
    }
}