package com.busanit501.boot501.shop.repository;


import com.busanit501.boot501.shop.entity.Cart;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CartRepository extends JpaRepository<Cart, Long> {

    // 합치기 수정
    Cart findByMemberMid(String memberMid);

}