import { lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

/****Layouts*****/
const FullLayout = lazy(() => import("../layouts/FullLayout.js"));

/***** Pages *****/
const MemberTables = lazy(() => import("../views/ui/MembersTables"));
const MemberDetailForm = lazy(() => import("../views/ui/MemberDetailForm"));
const DogTables = lazy(() => import("../views/ui/DogTables.js"));
const DogAddFrom = lazy(() => import("../views/ui/DogAddForm.js"));
const DogDetailForm = lazy(() => import("../views/ui/DogDetailForm.js"));
const ShopAddFrom = lazy(() => import("../views/ui/ShopAddForm.js"));
const ShopTables = lazy(() => import("../views/ui/ShopsTables"));
const ShopDetailForm = lazy(() => import("../views/ui/ShopDetailForm.js"));
const StockForm = lazy(() => import("../components/StockForm"));
const BoardTables = lazy(() => import("../views/ui/BoardsTables"));
const BoardDetailForm = lazy(() => import("../views/ui/BoardDetailForm.js"));
const BoardAddFrom = lazy(() => import("../views/ui/BoardAddForm.js"));
const AuctionAddFrom = lazy(() => import("../views/ui/AuctionAddForm.js"));
const AuctionTables = lazy(() => import("../views/ui/AuctionsTables"));
const OrderTables = lazy(() => import("../views/ui/OrdersTables"));

/*****Routes******/
const ThemeRoutes = () => {
  console.log("status admin");

  return (
    <Routes>
      <Route path="/" element={<FullLayout />}>
        {/* /admin에 직접 접근 시 MemberTables로 이동 */}
        <Route index element={<MemberTables />} />
        <Route path="membertable" element={<MemberTables />} />
        <Route path="memberdetailform/:email" element={<MemberDetailForm />} />
        <Route path="dogtable" element={<DogTables />} />
        <Route path="dogaddform" element={<DogAddFrom />} />
        <Route path="dogdetailform/:dogId" element={<DogDetailForm />} />
        <Route path="shoptable" element={<ShopTables />} />
        <Route path="shopaddform" element={<ShopAddFrom />} />
        <Route path="shopdetailform/:shopId" element={<ShopDetailForm />} />
        <Route path="stockform/:shopId" element={<StockForm />} />
        <Route path="boardtable" element={<BoardTables />} />
        <Route path="boarddetailform/:boardId" element={<BoardDetailForm />} />
        <Route path="boardaddform" element={<BoardAddFrom />} />
        <Route path="auctionaddform/:shopId" element={<AuctionAddFrom />} />
        <Route path="auctiontable" element={<AuctionTables />} />
        <Route path="ordertable" element={<OrderTables />} />

        {/* /admin 경로가 아닌 경우, /admin으로 리디렉션 */}
        <Route path="*" element={<Navigate to="/admin" replace />} />
      </Route>
    </Routes>
  );
};

export default ThemeRoutes;
