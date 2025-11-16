package com.busanit501.boot501.shop.service;


import com.busanit501.boot501.shop.dto.ItemFormDto;
import com.busanit501.boot501.shop.dto.ItemImgDto;
import com.busanit501.boot501.shop.dto.ItemSearchDto;
import com.busanit501.boot501.shop.dto.MainItemDto;
import com.busanit501.boot501.shop.entity.CartItem;
import com.busanit501.boot501.shop.entity.Item;
import com.busanit501.boot501.shop.entity.ItemImg;
import com.busanit501.boot501.shop.entity.OrderItem;
import com.busanit501.boot501.shop.repository.CartItemRepository;
import com.busanit501.boot501.shop.repository.ItemImgRepository;
import com.busanit501.boot501.shop.repository.ItemRepository;
import com.busanit501.boot501.shop.repository.OrderItemRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class ItemService {

    private final ItemRepository itemRepository;

    private final ItemImgService itemImgService;

    private final ItemImgRepository itemImgRepository;

    private final CartItemRepository cartItemRepository;

    private final OrderItemRepository orderItemRepository;


    public Long saveItem(ItemFormDto itemFormDto, List<MultipartFile> itemImgFileList) throws Exception{

        //상품 등록
        Item item = itemFormDto.createItem();
        itemRepository.save(item);

        //이미지 등록
        for(int i=0;i<itemImgFileList.size();i++){
            ItemImg itemImg = new ItemImg();
            itemImg.setItem(item);

            if(i == 0)
                itemImg.setRepimgYn("Y");
            else
                itemImg.setRepimgYn("N");

            itemImgService.saveItemImg(itemImg, itemImgFileList.get(i));
        }

        return item.getId();
    }

    @Transactional(readOnly = true)
    public ItemFormDto getItemDtl(Long itemId){
        List<ItemImg> itemImgList = itemImgRepository.findByItemIdOrderByIdAsc(itemId);
        List<ItemImgDto> itemImgDtoList = new ArrayList<>();
        for (ItemImg itemImg : itemImgList) {
            ItemImgDto itemImgDto = ItemImgDto.of(itemImg);
            itemImgDtoList.add(itemImgDto);
        }

        Item item = itemRepository.findById(itemId)
                .orElseThrow(EntityNotFoundException::new);
        ItemFormDto itemFormDto = ItemFormDto.of(item);
        itemFormDto.setItemImgDtoList(itemImgDtoList);
        return itemFormDto;
    }

    public Long updateItem(ItemFormDto itemFormDto, List<MultipartFile> itemImgFileList) throws Exception{
        //상품 수정
        Item item = itemRepository.findById(itemFormDto.getId())
                .orElseThrow(EntityNotFoundException::new);
        item.updateItem(itemFormDto);
        List<Long> itemImgIds = itemFormDto.getItemImgIds();

        //이미지 등록
        for(int i=0;i<itemImgFileList.size();i++){
            itemImgService.updateItemImg(itemImgIds.get(i),
                    itemImgFileList.get(i));
        }

        return item.getId();
    }

    //상품 삭제
    public void deleteItem(Long item_id) throws Exception {
        //카트에 담긴 상품 삭제
        Optional<CartItem> cartItemResult = cartItemRepository.findById(item_id);
        if(cartItemResult.isPresent()){
            cartItemRepository.deleteById(item_id);
        }
        //주문에 담긴 상품 삭제
        Optional<OrderItem> orderItemResult = orderItemRepository.findById(item_id);
        if (orderItemResult.isPresent()){
            orderItemRepository.deleteById(item_id);
        }
        // 상품의 이미지들 삭제
        itemImgService.deleteItemImg(item_id);

        // 상품 삭제
        itemRepository.deleteById(item_id);



    }

    @Transactional(readOnly = true)
    public Page<Item> getAdminItemPage(ItemSearchDto itemSearchDto, Pageable pageable){
        return itemRepository.getAdminItemPage(itemSearchDto, pageable);
    }

    @Transactional(readOnly = true)
    public Page<MainItemDto> getMainItemPage(ItemSearchDto itemSearchDto, Pageable pageable){
        return itemRepository.getMainItemPage(itemSearchDto, pageable);
    }

}