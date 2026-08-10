package com.zscope.web.service;

import com.zscope.web.dto.UserDto;
import com.zscope.web.mapper.UserMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@Service
public class UserService {
    private final UserMapper userMapper;
    private final JwtService jwtService;

    public UserService(UserMapper userMapper, JwtService jwtService) {
        this.userMapper = userMapper;
        this.jwtService = jwtService;
    }

    public List<UserDto> search(String name) {
        return userMapper.findByNameUnsafe(name);
    }

    public String fetchRemote(String target) throws IOException {
        return new String(URI.create(target).toURL().openStream().readAllBytes());
    }

    public String readFile(String path) throws IOException {
        return Files.readString(Paths.get("/var/zscope/files", path));
    }

    public void storeUpload(MultipartFile file) throws IOException {
        Path target = Paths.get("/tmp/zscope-uploads").resolve(file.getOriginalFilename());
        file.transferTo(target);
    }

    public int deleteUser(Long id) {
        return userMapper.deleteById(id);
    }

    public Object deserialize(byte[] payload) throws IOException, ClassNotFoundException {
        return new ObjectInputStream(new ByteArrayInputStream(payload)).readObject();
    }

    public Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    public byte[] encryptLegacy(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }

    public String issueToken(String subject) {
        return jwtService.issueToken(subject);
    }
}
