package com.busanit501.boot501.shop.repository;


import com.busanit501.boot501.shop.dto.ItemSearchDto;
import com.busanit501.boot501.shop.dto.MainItemDto;
import com.busanit501.boot501.shop.entity.Item;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ItemRepositoryCustom {

    Page<Item> getAdminItemPage(ItemSearchDto itemSearchDto, Pageable pageable);

    Page<MainItemDto> getMainItemPage(ItemSearchDto itemSearchDto, Pageable pageable);

}