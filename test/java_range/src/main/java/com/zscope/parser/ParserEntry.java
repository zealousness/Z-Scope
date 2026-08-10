package com.zscope.parser;

import com.alibaba.fastjson2.JSON;
import com.thoughtworks.xstream.XStream;
import freemarker.template.Configuration;
import freemarker.template.Template;
import org.mvel2.MVEL;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.yaml.snakeyaml.Yaml;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathFactory;
import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ParserEntry {
    public Object nativeDeserialize(byte[] payload) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(payload)).readObject();
    }

    public Object thirdPartyDeserialize(String payload) {
        Object fastjson = JSON.parseObject(payload, Object.class);
        Object yaml = new Yaml().load(payload);
        Object xml = new XStream().fromXML(payload);
        return fastjson != null ? fastjson : yaml != null ? yaml : xml;
    }

    public Object xmlDecoderDeserialize(byte[] payload) {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(payload));
        return decoder.readObject();
    }

    public Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    public String evaluateXPath(String username, Document document) throws Exception {
        return XPathFactory.newInstance()
            .newXPath()
            .evaluate("//user[name='" + username + "']", document);
    }

    public String renderTemplate(String templateSource) throws Exception {
        Template template = new Template(
            "dynamic",
            new StringReader(templateSource),
            new Configuration(Configuration.VERSION_2_3_32)
        );
        StringWriter writer = new StringWriter();
        template.process(Map.of("user", "benchmark"), writer);
        return writer.toString();
    }

    public Object evaluateExpression(String expression) {
        return MVEL.eval(expression);
    }

    public boolean regexMatch(String expression, String value) {
        return Pattern.compile(expression).matcher(value).matches();
    }

    public Path unzip(InputStream archive) throws Exception {
        ZipInputStream zipInputStream = new ZipInputStream(archive);
        ZipEntry entry = zipInputStream.getNextEntry();
        Path target = Paths.get("/tmp/zscope-unzip").resolve(entry.getName());
        Files.copy(zipInputStream, target);
        return target;
    }
}
