import React from "react";
import { useNavigate } from "react-router-dom";
import Box from "@mui/material/Box";
import Accordion from "@mui/material/Accordion";
import AccordionSummary from "@mui/material/AccordionSummary";
import AccordionDetails from "@mui/material/AccordionDetails";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import RestaurantIcon from "@mui/icons-material/Restaurant";
import ToysIcon from "@mui/icons-material/Toys";
import ChairIcon from "@mui/icons-material/Chair";
import StrollerIcon from "@mui/icons-material/Stroller";
import ShoppingCartIcon from "@mui/icons-material/ShoppingCart";
import GavelIcon from "@mui/icons-material/Gavel";
import styled from "styled-components";

const Sidebar = ({ setSelectedCategory }) => {
  const navigate = useNavigate();

  const menuItemsGroup1 = [
    { text: "식품", icon: <RestaurantIcon />, category: 0 },
    { text: "장난감", icon: <ToysIcon />, category: 1 },
    { text: "가구", icon: <ChairIcon />, category: 2 },
    { text: "유모차", icon: <StrollerIcon />, category: 3 },
  ];

  const menuItemsGroup2 = [
    { text: "장바구니", icon: <ShoppingCartIcon />, link: "/cart" },
    { text: "실시간 경매", icon: <GavelIcon />, link: "/auction" },
  ];

  const handleCategorySelect = (item) => {
    if (setSelectedCategory) {
      setSelectedCategory(item.category);
    }
    navigate(`/shop?category=${item.category}`);
  };

  return (
    <SidebarContainer>
      <AccordionWrapper>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <ListItemText primary="카테고리" />
        </AccordionSummary>
        <AccordionDetails>
          <List>
            {menuItemsGroup1.map((item) => (
              <ListItem key={item.text}>
                <ListItemButton onClick={() => handleCategorySelect(item)}>
                  <ListItemIcon>{item.icon}</ListItemIcon>
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </AccordionDetails>
      </AccordionWrapper>

      <AccordionWrapper>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <ListItemText primary="기타 기능" />
        </AccordionSummary>
        <AccordionDetails>
          <List>
            {menuItemsGroup2.map((item) => (
              <ListItem key={item.text}>
                <ListItemButton onClick={() => navigate(item.link)}>
                  <ListItemIcon>{item.icon}</ListItemIcon>
                  <ListItemText primary={item.text} />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </AccordionDetails>
      </AccordionWrapper>
    </SidebarContainer>
  );
};

export default Sidebar;

const SidebarContainer = styled(Box)`
  width: 100%;
  max-width: 250px;
  min-width: 200px;
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  padding: 10px;
  height: 100%;
  min-height: 1200px;
  overflow-y: auto;
`;

const AccordionWrapper = styled(Accordion)`
  margin-bottom: 10px;
  background-color: #ffffff;
  border: none;
  box-shadow: none;
  & .MuiAccordionSummary-root {
    background-color: #ffffff;
  }
  & .MuiAccordionDetails-root {
    padding: 0;
  }
`;
