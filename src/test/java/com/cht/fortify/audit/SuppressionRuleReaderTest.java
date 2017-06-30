package com.cht.fortify.audit;

import com.cht.fortify.rule.SuppressionRule;
import com.fortify.jaxb.fvdl.Vulnerability;
import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SuppressionRuleReaderTest {

    @Test
    public void testRead() throws Exception {
        URL resource = Thread.currentThread().getContextClassLoader().getResource("suppression-rule.yml");

        SuppressionRuleReader reader = new SuppressionRuleReader();
        SuppressionRule rule = reader.read(new File(resource.getFile()));

        assertThat(rule.getBuild().getId()).isEqualTo("rcs");

        List<Vulnerability> vulnerabilities = rule.getVulnerabilities();
        assertThat(vulnerabilities)
                .hasSize(2)
                .element(0)
                    .hasFieldOrPropertyWithValue("classInfo.type", "Access Control")
                    .hasFieldOrPropertyWithValue("classInfo.subtype", "Database");
    }

}
