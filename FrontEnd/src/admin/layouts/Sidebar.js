import {Button, Nav, NavItem} from "reactstrap";
import {Link, useLocation} from "react-router-dom";
import user1 from "../assets/images/users/user4.jpg";
import probg from "../assets/images/bg/download.jpg";
import "../assets/scss/style.scss"
import React, {useContext} from "react";
import {AuthContext} from "../../token/AuthContext";

const navigation = [
    {
        title: "회원",
        href: "/admin/membertable",
        icon: "bi bi-people",
    },
    {
        title: "유기견",
        href: "/admin/dogtable",
        icon: "bi bi-balloon-heart",
    },
    {
        title: "애견용품",
        href: "/admin/shoptable",
        icon: "bi bi-bag",
    },
    {
        title: "경매",
        href: "/admin/auctiontable",
        icon: "bi bi-basket",
    },
    {
        title: "판매내역",
        href: "/admin/ordertable",
        icon: "bi bi-clipboard2",
    },
    {
        title: "게시판",
        href: "/admin/boardtable",
        icon: "bi bi-clipboard2",
    },
];

const Sidebar = () => {
    const showMobilemenu = () => {
        document.getElementById("sidebarArea").classList.toggle("showSidebar");
    };
    let location = useLocation();
    const {isAuthenticated, logout} = useContext(AuthContext);

    return (
        <div>
            <div className="d-flex align-items-center"></div>
            <div
                className="profilebg"
                style={{background: `url(${probg}) no-repeat`}}
            >
                <div className="p-3 d-flex">
                    <img src={user1} alt="user" width="50" className="rounded-circle"/>
                    <Button
                        color="white"
                        className="ms-auto text-white d-lg-none"
                        onClick={() => showMobilemenu()}
                    >
                        <i className="bi bi-x"></i>
                    </Button>
                </div>

            </div>
            <div className="p-3 mt-2">
                <Nav vertical className="sidebarNav">
                    {navigation.map((navi, index) => (
                        <NavItem key={index} className="sidenav-bg">
                            <Link
                                to={navi.href}
                                className={
                                    location.pathname === navi.href
                                        ? "active nav-link py-3"
                                        : "nav-link text-secondary py-3"
                                }
                            >
                                <i className={navi.icon}></i>
                                <span className="ms-3 d-inline-block">{navi.title}</span>
                            </Link>
                        </NavItem>
                    ))}
                    <NavItem>
                        <Button
                            onClick={() => logout()}
                            className="nav-link text-secondary py-3"
                            style={{background: 'none', border: 'none'}}
                        >
                            <i className="bi bi-box-arrow-right"></i>
                            <span className="ms-3 d-inline-block">로그아웃</span>
                        </Button>
                    </NavItem>
                </Nav>
            </div>
        </div>
    );
};

export default Sidebar;
