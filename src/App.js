import "./App.css";
import Main from "./pages/MainPage";
import NavBar from "./components/Main/NavBar";
import Footer from "./components/Main/Footer";
import FreeBoardPage from "./pages/Board/FreeBoardPage";
import OneOnOneBoardPage from "./pages/Board/OneOnOneBoardPage";
import BoardFindOnePage from "./pages/Board/BoardFindOnePage";
import BoardRegister from "./pages/Board/BoardRegisterPage";
import BoardEdit from "./pages/Board/BoardEditPage";
import BoardRemove from "./pages/Board/BoardDeletePage";
import Cart from "./components/Cart";
import DogDetail from "./pages/Dog/DogDetail";
import DogList from "./pages/Dog/DogList";
import ShopPage from "./pages/ShopPage";
import ShopDetailPage from "./pages/ShopDetailPage";
import SuccessPage from "./pages/Checkout/SuccessPage";
import FailPage from "./pages/Checkout/FailPage";
import OrderDetails from "./myPage/OrderDetails"; 

import { Routes, Route, useLocation } from "react-router-dom";

import GlobalStyle from "./config/GlobalStyle";
import SignIn from "./pages/Memeber/SignIn";
import SignUp from "./pages/Memeber/SignUp";
import Button from "./components/Button";

import AuctionMain from "./pages/Auction/AuctionMain";
import Auction from "./pages/Auction/Auction";

import Mypage from "./pages/Memeber/Mypage";

import { useEffect } from "react";
import ProtectedRoute from "./token/ProtectedRoute";
import AdminRoutes from "./admin/routes/Router";

import CheckoutPage from "./pages/Checkout/CheckoutPage";
import GlobalLoading from "./config/GlobalLoading";
import {
  setupInterceptors,
  setupNoTokenInterceptors,
} from "./token/AxiosConfig";
import { useLoading } from "./config/LodingContext";
let interceptorsInitialized = false;

function App() {
  const { setLoading } = useLoading();
  const location = useLocation();
  const hideNavAndFotter = location.pathname.startsWith("/admin");

  return (
    <>
      <div className="App">
        <GlobalStyle />
        <GlobalLoading />
        {!hideNavAndFotter && <NavBar />}

        <Routes>
          {/* 메인 Page  */}
          <Route path="/" element={<Main />} />

          {/* 쇼핑몰Page */}
          <Route path="/shop" element={<ShopPage />} />
          <Route path="/shop/:shopId" element={<ShopDetailPage />} />

          {/* 결제 Page */}
          <Route path="/success" element={<SuccessPage />} />
          <Route path="/fail" element={<FailPage />} />

          {/* 강아지 사이트 */}
          <Route path="/dogList" element={<DogList />} />
          <Route path="/dog/:dogId" element={<DogDetail />} />

          {/* 게시판 사이트 */}
          <Route path="/freeBoard" element={<FreeBoardPage />} />
          <Route path="/oneOnOneBoard" element={<OneOnOneBoardPage />} />
          <Route path="/board/register" element={<BoardRegister />} />
          <Route path="/board/edit/:boardId" element={<BoardEdit />} />
          <Route path="/board/remove/:boardId" element={<BoardRemove />} />

          {/* 회원 관리 */}
          <Route path="/signIn" element={<SignIn />} />
          <Route path="/signUp" element={<SignUp />} />

          {/* 회원 전용 Route */}
          <Route
            element={
              <ProtectedRoute allowedRoles={["ROLE_USER", "ROLE_PREMIUM"]} />
            }
          >
            <Route path="/order/findOne/:orderId" element={<OrderDetails />} /> {/* OrderDetails 경로 설정 */}

            <Route path="/cart" element={<Cart />} />
            <Route path="/mypage" element={<Mypage />} />
            <Route path="/checkout" element={<CheckoutPage />} />
            <Route path="/board/:boardId" element={<BoardFindOnePage />} />
          </Route>

          {/* 경매 Route */}
          <Route path="/auction" element={<AuctionMain />} />
          <Route element={<ProtectedRoute allowedRoles={["ROLE_PREMIUM"]} />}>
            <Route path="/auction/bid" element={<Auction />} />
          </Route>

          {/* Admin Route */}
          <Route
            element={<ProtectedRoute allowedRoles={["ROLE_ADMIN"]} />}
          >
            <Route path="/admin/*" element={<AdminRoutes />} />
          </Route>
        </Routes>

        {!hideNavAndFotter && <Button />}
        {!hideNavAndFotter && <Footer />}
      </div>
    </>
  );
}

export default App;
