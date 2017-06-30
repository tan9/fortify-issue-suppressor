package com.cht.fortify.audit;

import com.cht.fortify.rule.SuppressionRule;
import com.fortify.jaxb.fvdl.FVDL;
import com.fortify.model.Audit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.ansi.AnsiColor;
import org.springframework.boot.ansi.AnsiOutput;
import org.springframework.boot.ansi.AnsiStyle;
import org.springframework.stereotype.Component;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Help.Ansi;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import javax.xml.bind.JAXB;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipFile;

@Slf4j
@Component
@Command(name = "FPR Issue Suppressor",
        description = "Suppress specified issues in Fortify FPR report.",
        footer = "Copyright (c) 2017")
public class IssueSuppressor implements CommandLineRunner {

    private static final String DEFAULT_INPUT_FILE = "./report.fpr";
    private static final String DEFAULT_OUTPUT_FILE = "./report-suppressed.fpr";
    private static final String DEFAULT_SUPPRESSION_RULE = "./suppression_rule.yml";

    private static final String XML_AUDIT = "audit.xml";

    @Option(names = {"-r", "--rule"},
            description = "Suppression rule YAML file. (Default to \"" + DEFAULT_SUPPRESSION_RULE + "\")")
    private File suppressionRule = new File(DEFAULT_SUPPRESSION_RULE);

    @Option(names = {"-h", "--help"}, description = "Show this help message.", help = true)
    private boolean helpRequested = false;

    @Parameters(index = "0", paramLabel = "FPR_FILE_IN", arity = "0..1",
            description = "FPR file to be processed. (Default to \"" + DEFAULT_INPUT_FILE + "\")")
    private File fprIn = new File(DEFAULT_INPUT_FILE);

    @Parameters(index = "1", paramLabel = "FPR_FILE_OUT", arity = "0..1",
            description = "Where to store the processed FPR file. (Default to \"" + DEFAULT_OUTPUT_FILE + "\")")
    private File fprOut = new File(DEFAULT_OUTPUT_FILE);

    // @Autowired TODO find out why autowire is not working
    private FvdlReader fvdlReader = new FvdlReader();

    // @Autowired
    private SuppressionRuleReader ruleReader = new SuppressionRuleReader();

    // @Autowired
    private AuditGenerator auditGenerator = new AuditGenerator();

    @Override
    public void run(String... args) throws Exception {
        CommandLine commandLine = new CommandLine(this);
        try {
            commandLine.parse(args);

        } catch (CommandLine.ParameterException e) {
            err(e.getMessage());
            commandLine.usage(System.out, getAnsi());
            throw e;
        }

        if (helpRequested) {
            commandLine.usage(System.out, getAnsi());
            log.info("Help requested, terminating after showing usage.");
            return;
        }

        try {
            run();

        } catch (FileNotFoundException e) {
            err("Error: " + e.getMessage());
            commandLine.usage(System.out, getAnsi());
            throw e;

        } catch (Exception e) {
            err("Error: " + e.getMessage());
            throw e;
        }
    }

    private void run() throws Exception {
        log("Loading FVDL from ", AnsiColor.YELLOW, fprIn, AnsiColor.DEFAULT, "...");
        FVDL fvdl = fvdlReader.read(new ZipFile(fprIn));
        log("FVDL loaded,",
                " found ", AnsiColor.RED, fvdl.getVulnerabilities().getVulnerability().size(), AnsiColor.DEFAULT, " vulnerabilities.");

        log("Loading suppression rule from ", AnsiColor.YELLOW, suppressionRule, AnsiColor.DEFAULT, "...");
        SuppressionRule rule = ruleReader.read(suppressionRule);
        log("Suppression rule for build \"", AnsiColor.YELLOW, rule.getBuild().getId(), AnsiColor.DEFAULT, "\" loaded,",
                " found ", AnsiColor.YELLOW, rule.getVulnerabilities().size(), AnsiColor.DEFAULT, " vulnerabilities suppression rule.");

        log("Generating content of ", AnsiColor.YELLOW, XML_AUDIT, AnsiColor.DEFAULT, "...");
        Audit audit = auditGenerator.suppress(fvdl, rule);
        audit.getProjectInfo().setName(fprIn.getName());
        log("Audit of ", AnsiColor.RED, audit.getIssueList().getIssue().size(), AnsiColor.DEFAULT, " issue suppression generated.");

        Files.copy(fprIn.toPath(), fprOut.toPath(), StandardCopyOption.REPLACE_EXISTING);
        log("File copied from ", AnsiColor.YELLOW, fprIn, AnsiColor.DEFAULT, " to ", AnsiColor.YELLOW, fprOut, AnsiColor.DEFAULT, ".");

        Map<String, String> env = new HashMap<>();
        env.put("create", "true");

        URI uri = URI.create("jar:" + fprOut.toPath().toUri());
        try (FileSystem fs = FileSystems.newFileSystem(uri, env)) {
            Path nf = fs.getPath(XML_AUDIT);
            try (OutputStream outputStream = Files.newOutputStream(nf, StandardOpenOption.CREATE)) {
                JAXB.marshal(audit, outputStream);
                log("Wrote ", AnsiColor.YELLOW, XML_AUDIT, AnsiColor.DEFAULT, " to ", AnsiColor.YELLOW, fprOut, AnsiColor.DEFAULT, ".");
            }
        }
        log(AnsiStyle.BOLD, "FPR with suppression generated successfully!");
    }

    private Ansi getAnsi() {
        try {
            Method isEnabledMethod = AnsiOutput.class.getDeclaredMethod("isEnabled");
            isEnabledMethod.setAccessible(true);
            return Boolean.TRUE.equals(isEnabledMethod.invoke(AnsiOutput.class)) ? Ansi.ON : Ansi.OFF;

        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
            throw new IssueSuppressorException("Unable to determine ansi color support from Spring Boot.", e);
        }
    }

    private void log(Object... message) {
        String ansiMessage = AnsiOutput.toString(message);
        System.out.println(ansiMessage);
        log.info(ansiMessage);
    }

    private void err(String message) {
        System.err.println(message);
    }
}
