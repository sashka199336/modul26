package com.globus.modul26.util;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;

@Component
public class LogRotator {

    private static final String LOG_FILE = "logs/cef.log";
    private static final String BACKUP_DIR = "log/cef/backup";
    private static final String ARCHIVE_DIR = "log/cef/archive";


    private static final DateTimeFormatter DAY_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter MONTH_FMT = DateTimeFormatter.ofPattern("yyyy-MM");

    @PostConstruct
    public void onStartup() throws IOException {
        Files.createDirectories(Paths.get(BACKUP_DIR));
        Files.createDirectories(Paths.get(ARCHIVE_DIR));

        LocalDate today = LocalDate.now();
        String todayName = "cef-" + DAY_FMT.format(today) + ".log";
        String monthName = "cef-" + MONTH_FMT.format(today) + ".tar.gz";


        boolean needDailyBackup = true;
        try (Stream<Path> files = Files.list(Paths.get(BACKUP_DIR))) {
            needDailyBackup = files
                    .map(path -> path.getFileName().toString())
                    .noneMatch(fname -> fname.equals(todayName));
        }

        if (needDailyBackup) {
            Files.copy(Paths.get(LOG_FILE), Paths.get(BACKUP_DIR, todayName), StandardCopyOption.REPLACE_EXISTING);
            System.out.println("Daily log backup created: " + todayName);
        }


        boolean needMonthlyArchive = true;
        try (Stream<Path> files = Files.list(Paths.get(ARCHIVE_DIR))) {
            needMonthlyArchive = files
                    .map(path -> path.getFileName().toString())
                    .noneMatch(fname -> fname.equals(monthName));
        }

        if (needMonthlyArchive) {

            LocalDate firstDayOfMonth = today.withDayOfMonth(1);
            LocalDate prevMonth = firstDayOfMonth.minusDays(1);
            String prevMonthPrefix = "cef-" + MONTH_FMT.format(prevMonth);

            List<Path> filesToArchive = new ArrayList<>();
            try (Stream<Path> files = Files.list(Paths.get(BACKUP_DIR))) {
                filesToArchive = files
                        .filter(f -> f.getFileName().toString().startsWith(prevMonthPrefix))
                        .toList();
            }
            if (!filesToArchive.isEmpty()) {
                Path archivePath = Paths.get(ARCHIVE_DIR, "cef-" + MONTH_FMT.format(prevMonth) + ".tar.gz");
                createTarGzArchive(filesToArchive, archivePath);
                System.out.println("Monthly archive created: " + archivePath.getFileName());
                // Можно удалить старые бэкапы, если надо
            }
        }
    }

    private void createTarGzArchive(List<Path> files, Path archivePath) throws IOException {

        try (FileOutputStream fos = new FileOutputStream(archivePath.toFile());
             GZIPOutputStream gos = new GZIPOutputStream(fos)) {
            for (Path file : files) {
                Files.copy(file, gos);
            }
        }
    }
}