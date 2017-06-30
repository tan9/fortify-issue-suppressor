package com.cht.fortify.audit;

import com.fortify.jaxb.fvdl.FVDL;
import org.springframework.stereotype.Component;

import javax.xml.bind.JAXB;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

@Component
public class FvdlReader {

    public FVDL read(ZipFile fprFile) {
        Optional<? extends ZipEntry> fvdl = fprFile.stream()
                .filter(entry -> entry.getName().endsWith(".fvdl")).findFirst();
        if (fvdl.isPresent()) {
            try (InputStream inputStream = fprFile.getInputStream(fvdl.get())) {
                return read(inputStream);

            } catch (IOException e) {
                throw new IssueSuppressorException("Cannot read FVDL from FPR file.", e);
            }

        } else {
            throw new IssueSuppressorException("Cannot found FVDL from FPR file: " + fprFile);
        }
    }

    public FVDL read(InputStream stream) {
        return JAXB.unmarshal(stream, FVDL.class);
    }
}
