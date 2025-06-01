package com.globus.modul26.integrations;

import com.globus.modul26.model.SecurityLog;
import org.springframework.stereotype.Component;

@Component
public class SIEMExporter {
    public void exportInCEF(SecurityLog event) {
        // Преобразуй событие в формат CEF
        String cef = String.format("CEF:0|Globus|modul26|1.0|%s|%s|severity| eventId=%d src=%s",
                event.getEventType(), event.getDeviceInfo(), event.getId(), event.getIpAddress());

        System.out.println("SIEM CEF: " + cef);
    }
}