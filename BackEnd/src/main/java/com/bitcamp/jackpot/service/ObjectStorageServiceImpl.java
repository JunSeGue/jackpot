package com.bitcamp.jackpot.service;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.CannedAccessControlList;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.bitcamp.jackpot.config.NaverConfig;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.UUID;

@Service
public class ObjectStorageServiceImpl implements ObjectStorageService{

    String bucketName ="jackpot-ai08";

    final AmazonS3 s3;

    public ObjectStorageServiceImpl(NaverConfig naverConfig) {
        this.s3 = AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(
                        naverConfig.getAccessKey(), naverConfig.getSecretKey())))
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(
                        naverConfig.getEndPoint(), naverConfig.getRegionName()))
                .build();
    }

    @Override
    public String uploadFile(String directoryPath, MultipartFile file) {
        if (file.isEmpty()) return null;

        try (InputStream fileIn = file.getInputStream()) {
            String fileName = UUID.randomUUID().toString();

            ObjectMetadata objectMetadata = new ObjectMetadata();
            objectMetadata.setContentType(file.getContentType());

            PutObjectRequest objectRequest = new PutObjectRequest(bucketName, directoryPath + fileName, fileIn, objectMetadata)
                    .withCannedAcl(CannedAccessControlList.PublicRead);

            s3.putObject(objectRequest);
            //이건 그냥 objectStorage url
            return s3.getUrl(bucketName, directoryPath + fileName).toString();

            //이건 imageOptimizer 형식(imgOpt프로젝트 주소 뒤에 storage의 디렉토리), 실제 리턴할 때는 DTO에서 opt형식 붙여줘야 함.
            //return "https://we7dnye15245.edge.naverncp.com/mLmykgysED/" + directoryPath + fileName;
        }catch ( Exception e ) {
            throw new RuntimeException("파일 업로드 오류",e);
        }
    }
}
