package com.busanit501.boot501.service;

import com.busanit501.boot501.shop.service.ItemService;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
@Log4j2
public class ItemServiceTests {
    @Autowired
    private ItemService itemService;

    @Test
    public void itemDeleteTest() throws Exception {
        Long id = 103L;
        itemService.deleteItem(id);

    }

}
