package com.busanit501.boot501.shop.controller;

import com.busanit501.boot501.shop.dto.CartDetailDto;
import com.busanit501.boot501.shop.dto.CartItemDto;
import com.busanit501.boot501.shop.dto.CartOrderDto;
import com.busanit501.boot501.shop.service.CartService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@Controller
@RequiredArgsConstructor
@Log4j2
public class CartController {

    private final CartService cartService;

    @PostMapping(value = "/cart")
    public @ResponseBody ResponseEntity order(@RequestBody @Valid CartItemDto cartItemDto, BindingResult bindingResult, Principal principal) {

        if (bindingResult.hasErrors()) {
            StringBuilder sb = new StringBuilder();
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();

            for (FieldError fieldError : fieldErrors) {
                sb.append(fieldError.getDefaultMessage());
            }

            return new ResponseEntity<String>(sb.toString(), HttpStatus.BAD_REQUEST);
        }
        log.info("CartController 1 cartItemDto : " + cartItemDto);
        String mid = principal.getName();
        Long cartItemId;
        log.info("CartController 2 mid = email : " + mid);

        try {
            log.info("CartController 3 addCart 전 : ");
            cartItemId = cartService.addCart(cartItemDto, mid);
            log.info("CartController 4 addCart 후 : ");
        } catch (Exception e) {
            return new ResponseEntity<String>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity<Long>(cartItemId, HttpStatus.OK);
    }

    @GetMapping(value = "/cart")
    public String orderHist(Principal principal, Model model) {
        log.info("CartController 1 orderHist ");
        List<CartDetailDto> cartDetailList = cartService.getCartList(principal.getName());
        log.info("CartController 2 orderHist ");
        log.info("CartController 2-2 principal.getName() :  " + principal.getName());
        log.info("CartController 3 cartDetailList.isEmpty :  " + cartDetailList.isEmpty());
        model.addAttribute("cartItems", cartDetailList);
        return "shop/cart/cartList";
    }

    @PatchMapping(value = "/cartItem/{cartItemId}")
    public @ResponseBody ResponseEntity updateCartItem(@PathVariable("cartItemId") Long cartItemId, int count, Principal principal) {

        if (count <= 0) {
            return new ResponseEntity<String>("최소 1개 이상 담아주세요", HttpStatus.BAD_REQUEST);
        } else if (!cartService.validateCartItem(cartItemId, principal.getName())) {
            return new ResponseEntity<String>("수정 권한이 없습니다.", HttpStatus.FORBIDDEN);
        }

        cartService.updateCartItemCount(cartItemId, count);
        return new ResponseEntity<Long>(cartItemId, HttpStatus.OK);
    }

    @DeleteMapping(value = "/cartItem/{cartItemId}")
    public @ResponseBody ResponseEntity deleteCartItem(@PathVariable("cartItemId") Long cartItemId, Principal principal) {

        if (!cartService.validateCartItem(cartItemId, principal.getName())) {
            return new ResponseEntity<String>("수정 권한이 없습니다.", HttpStatus.FORBIDDEN);
        }

        cartService.deleteCartItem(cartItemId);

        return new ResponseEntity<Long>(cartItemId, HttpStatus.OK);
    }

    @PostMapping(value = "/cart/orders")
    public @ResponseBody ResponseEntity orderCartItem(@RequestBody CartOrderDto cartOrderDto, Principal principal) {
        log.info("CartController /cart/orders 확인 1 :  orderCartItem ");
        List<CartOrderDto> cartOrderDtoList = cartOrderDto.getCartOrderDtoList();
        log.info("CartController /cart/orders 확인 2 :  cartOrderDtoList.isEmpty : " + cartOrderDtoList.isEmpty());
        if (cartOrderDtoList == null || cartOrderDtoList.size() == 0) {
            return new ResponseEntity<String>("주문할 상품을 선택해주세요", HttpStatus.FORBIDDEN);
        }

        for (CartOrderDto cartOrder : cartOrderDtoList) {
            log.info("CartController /cart/orders 확인 3 :  principal.getName() : " + principal.getName());
            log.info("CartController /cart/orders 확인 4 :  cartOrder.getCartItemId() : " + cartOrder.getCartItemId());
            if (!cartService.validateCartItem(cartOrder.getCartItemId(), principal.getName())) {
                return new ResponseEntity<String>("주문 권한이 없습니다.", HttpStatus.FORBIDDEN);
            }
        }
        log.info("CartController /cart/orders 확인 5 :  orderCartItem 전 ");
        Long orderId = cartService.orderCartItem(cartOrderDtoList, principal.getName());
        log.info("CartController /cart/orders 확인 6 :  orderId 후 : " + orderId);
        return new ResponseEntity<Long>(orderId, HttpStatus.OK);
    }

}