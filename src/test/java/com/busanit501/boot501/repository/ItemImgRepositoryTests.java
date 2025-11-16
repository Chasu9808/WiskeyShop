package com.busanit501.boot501.repository;

import com.busanit501.boot501.shop.entity.ItemImg;
import com.busanit501.boot501.shop.repository.ItemImgRepository;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
@Log4j2
public class ItemImgRepositoryTests {
    @Autowired
    private ItemImgRepository itemImgRepository;

    @Test
    public void findAllTest() {
        Long id = 103L;
        List<ItemImg> result = itemImgRepository.findByItemId(id);

        log.info(result);
    }
}
