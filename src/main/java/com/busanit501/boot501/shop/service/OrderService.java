package com.busanit501.boot501.shop.service;


import com.busanit501.boot501.domain.Member;
import com.busanit501.boot501.repository.MemberRepository;
import com.busanit501.boot501.shop.dto.OrderDto;
import com.busanit501.boot501.shop.dto.OrderHistDto;
import com.busanit501.boot501.shop.dto.OrderItemDto;
import com.busanit501.boot501.shop.entity.Item;
import com.busanit501.boot501.shop.entity.ItemImg;
import com.busanit501.boot501.shop.entity.Order;
import com.busanit501.boot501.shop.entity.OrderItem;
import com.busanit501.boot501.shop.repository.ItemImgRepository;
import com.busanit501.boot501.shop.repository.ItemRepository;
import com.busanit501.boot501.shop.repository.OrderRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class OrderService {

    private final ItemRepository itemRepository;

    // 합치기 수정
    private final MemberRepository memberRepository;

    private final OrderRepository orderRepository;

    private final ItemImgRepository itemImgRepository;

    public Long order(OrderDto orderDto, String mid){

        Item item = itemRepository.findById(orderDto.getItemId())
                .orElseThrow(EntityNotFoundException::new);

        // 합치기 수정

//        ShopMember shopMember = memberRepository.findByEmail(email);
        Optional<Member> result = memberRepository.findByMid(mid);
        Member Member = result.orElseThrow();

        List<OrderItem> orderItemList = new ArrayList<>();
        OrderItem orderItem = OrderItem.createOrderItem(item, orderDto.getCount());
        orderItemList.add(orderItem);
        // 합치기 수정
        Order order = Order.createOrder(Member, orderItemList);
        orderRepository.save(order);

        return order.getId();
    }

    @Transactional(readOnly = true)
    public Page<OrderHistDto> getOrderList(String mid, Pageable pageable) {

        List<Order> orders = orderRepository.findOrders(mid, pageable);
        Long totalCount = orderRepository.countOrder(mid);

        List<OrderHistDto> orderHistDtos = new ArrayList<>();

        for (Order order : orders) {
            OrderHistDto orderHistDto = new OrderHistDto(order);
            List<OrderItem> orderItems = order.getOrderItems();
            for (OrderItem orderItem : orderItems) {
                ItemImg itemImg = itemImgRepository.findByItemIdAndRepimgYn
                        (orderItem.getItem().getId(), "Y");
                OrderItemDto orderItemDto =
                        new OrderItemDto(orderItem, itemImg.getImgUrl());
                orderHistDto.addOrderItemDto(orderItemDto);
            }

            orderHistDtos.add(orderHistDto);
        }

        return new PageImpl<OrderHistDto>(orderHistDtos, pageable, totalCount);
    }

    @Transactional(readOnly = true)
    public boolean validateOrder(Long orderId, String mid){
        // 합치기 수정
//        ShopMember curShopMember = memberRepository.findByEmail(email);
        Optional<Member> result = memberRepository.findByMid(mid);
        Member curMember = result.orElseThrow();

        Order order = orderRepository.findById(orderId)
                .orElseThrow(EntityNotFoundException::new);
        // 합치기 수정
        Member savedMember = order.getMember();

        if(!StringUtils.equals(curMember.getEmail(), savedMember.getEmail())){
            return false;
        }

        return true;
    }

    public void cancelOrder(Long orderId){
        Order order = orderRepository.findById(orderId)
                .orElseThrow(EntityNotFoundException::new);
        order.cancelOrder();
    }

    public Long orders(List<OrderDto> orderDtoList, String mid){
// 합치기 수정
//        ShopMember shopMember = memberRepository.findByEmail(email);
        Optional<Member> result = memberRepository.findByMid(mid);
        Member Member = result.orElseThrow();

        List<OrderItem> orderItemList = new ArrayList<>();

        for (OrderDto orderDto : orderDtoList) {
            Item item = itemRepository.findById(orderDto.getItemId())
                    .orElseThrow(EntityNotFoundException::new);

            OrderItem orderItem = OrderItem.createOrderItem(item, orderDto.getCount());
            orderItemList.add(orderItem);
        }

        Order order = Order.createOrder(Member, orderItemList);
        orderRepository.save(order);

        return order.getId();
    }

}