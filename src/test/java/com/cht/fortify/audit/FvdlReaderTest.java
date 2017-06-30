package com.cht.fortify.audit;

import com.fortify.jaxb.fvdl.FVDL;
import org.junit.Test;

import java.net.URL;
import java.util.zip.ZipFile;

import static org.assertj.core.api.Assertions.assertThat;

public class FvdlReaderTest {

    @Test
    public void read() throws Exception {
        URL resource = Thread.currentThread().getContextClassLoader().getResource("fortify-result.fpr");

        FvdlReader reader = new FvdlReader();
        FVDL fvdl = reader.read(new ZipFile(resource.getFile()));

        assertThat(fvdl.getVulnerabilities().getVulnerability()).hasSize(2445);
    }
}
