package com.busanit501.boot501.service;

import com.busanit501.boot501.shop.repository.ItemImgRepository;
import com.busanit501.boot501.shop.service.FileService;
import com.busanit501.boot501.shop.service.ItemImgService;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class ItemImgServiceTests {

    @Value("${itemImgLocation}")
    private String itemImgLocation;

    @Autowired
    ItemImgService itemImgService;
    @Autowired
    ItemImgRepository itemImgRepository;
    @Autowired
    FileService fileService;

    @Test
    public void testDelete() throws Exception {
        Long id = 3L;
//        ItemImg savedItemImg = itemImgRepository.findById(id)
//                .orElseThrow(EntityNotFoundException::new);
//        //기존 이미지 파일 삭제
//        if(!StringUtils.isEmpty(savedItemImg.getImgName())) {
//            fileService.deleteFile(itemImgLocation+"/"+
//                    savedItemImg.getImgName());
//        }
//        itemImgRepository.deleteById(id);

       itemImgService.deleteItemImg(id);

    }

}
