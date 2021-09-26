package ac.at.tuwien.ifs.sepses.parser.impl;

import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.helper.DownloadUnzip;
import ac.at.tuwien.ifs.sepses.helper.Utility;
import ac.at.tuwien.ifs.sepses.helper.XMLParser;
import ac.at.tuwien.ifs.sepses.parser.Parser;
import ac.at.tuwien.ifs.sepses.parser.tool.Linker;
import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.vocab.CAPEC;
import ac.at.tuwien.ifs.sepses.vocab.TL;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.ResourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.topbraid.shacl.vocabulary.SH;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

public class TLParser implements Parser {

    private static final Logger log = LoggerFactory.getLogger(TLParser.class);

    private final String urlTL;
    private final String destDir;
    private final String outputDir;
    private final String rmlMetaModel;
    private final String rmlFile;
    private final String sparqlEndpoint;
    private final String namegraph;
    private final String active;
    private final Boolean isUseAuth;
    private final String user;
    private final String pass;

    private final Storage storage;

    public TLParser(Properties properties) {
        urlTL = properties.getProperty("TLUrl");
        destDir = properties.getProperty("InputDir") + "/threatlist";
        outputDir = properties.getProperty("OutputDir") + "/threatlist";
        rmlMetaModel = properties.getProperty("TLRMLTempFile");
        rmlFile = properties.getProperty("TLRMLFile");
        namegraph = properties.getProperty("TLNamegraph");
        active = properties.getProperty("TLActive");

        sparqlEndpoint = properties.getProperty("SparqlEndpoint");
        isUseAuth = Boolean.parseBoolean(properties.getProperty("UseAuth"));
        user = properties.getProperty("EndpointUser");
        pass = properties.getProperty("EndpointPass");

        storage = Utility.getStorage(properties);
    }

    public static void main(String[] args) throws Exception {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream("config.properties");
        prop.load(ip);
        ip.close();

        Parser parser = new TLParser(prop);
        parser.parse(false);
    }

    @Override public void parse(Boolean isShaclActive) throws IOException {

        if (!active.equals("Yes")) {
            log.warn("Sorry, THREAT LIST Parser is inactive.. please activate it in the config file !");

        } else {
            Model model = getModelFromLastUpdate();
            if (isShaclActive) {
                Model checkResults = Utility.validateWithShacl("shacl/tl.ttl", model);
                if (checkResults.contains(null, SH.conforms, ResourceFactory.createTypedLiteral(false))) {
                    throw new IOException("THREAT LIST Validation Error: " + checkResults.toString());
                }
                checkResults.close();
                log.info("TL Validation Succeeded");
            } else if (!model.isEmpty()) {
                String filename = saveModelToFile(model);
                storeFileInRepo(filename);
            }
            model.close();
        }
    }

    @Override public Model getModelFromLastUpdate() throws IOException {
        long start = System.currentTimeMillis() / 1000;
        long end;

        Model model = null;

        /**
        // Step 1 - Downloading CAPEC resource from the internet...
        log.info("Downloading CAPEX file from " + urlCAPEC);
        String capecFileName = urlCAPEC.substring(urlCAPEC.lastIndexOf("/") + 1);
        String destCAPECFile = destDir + "/" + capecFileName;
        String CAPECZipFile = DownloadUnzip.downloadResource(urlCAPEC, destCAPECFile);
        log.info("CAPEX file downloaded");

        // Step 2 - Unziping resource...
        log.info("Unzipping CAPEX file into ");
        String UnzipFile = DownloadUnzip.unzip(CAPECZipFile, destDir);
        log.info(UnzipFile + " - Done!");
        **/
        // Step 1 - Injecting xml file...
        String File = destDir+"/"+(("/") + 1);
        String TLXML = File;
        String fileName = TLXML.substring(TLXML.lastIndexOf("/") + 1);
        if (fileName.indexOf("\\") >= 0) {
            fileName = TLXML.substring(TLXML.lastIndexOf("\\") + 1);
        }
        log.info("adjusting filename: " + fileName);
        Path path = Paths.get(TLXML);
        String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        content = content.replaceAll("xmlns=\"http://capec.mitre.org/capec-3\"",
                "xmlns:1=\"http://capec.mitre.org/capec-3\"");
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));

        // Step 4 - Checking whether CAPEC is up-to-date ...
        log.info("Checking updates from " + sparqlEndpoint + " using graphname " + namegraph);
        Boolean cat = Utility.checkIsUpToDate(XMLParser.Parse(TLXML, rmlMetaModel), sparqlEndpoint, namegraph,
                CAPEC.ATTACK_PATTERN_CATALOG);
        if (cat) {
            log.info("THREAT LIST is up-to-date...! ");
            model = ModelFactory.createDefaultModel();

        } else {
            log.info("THREAT LIST is new...! ");

            //4. Parsing xml to rdf......
            model = parseTL(TLXML, rmlFile);
        }
        end = System.currentTimeMillis() / 1000;
        log.info("CAPEC parser finished in " + (end - start) + " seconds");

        return model;
    }

    @Override public String saveModelToFile(Model model) {
        return Utility.saveToFile(model, outputDir, urlTL);
    }

    @Override public void storeFileInRepo(String filename) {

        log.info("Store data to " + sparqlEndpoint + " using graph " + namegraph);
        storage.replaceData(filename, sparqlEndpoint, namegraph, isUseAuth, user, pass);
    }

    private Model parseTL(String capecXmlFile, String RMLFile) throws IOException {
        log.info("Parsing xml to rdf...  ");
        Model TLModel = XMLParser.Parse(capecXmlFile, RMLFile);
        Linker.updateCapecLinks(TLModel);
        Integer countTL = Utility.countInstance(TLModel, TL.TL);
        log.info("The number of THREAT LIST instances parsed: " + countTL);
        log.info("Parsing done..!");

        return TLModel;
    }
}
