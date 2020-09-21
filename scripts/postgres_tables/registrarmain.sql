--
-- PostgreSQL database dump
--

-- Dumped from database version 12.4
-- Dumped by pg_dump version 12.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: registrarmain; Type: TABLE; Schema: public; Owner: keylime
--

CREATE TABLE public.registrarmain (
    agent_id character varying(80) NOT NULL,
    key character varying,
    aik character varying,
    ek character varying,
    ekcert character varying,
    virtual integer,
    active integer,
    provider_keys text,
    regcount integer
);


ALTER TABLE public.registrarmain OWNER TO keylime;

--
-- Name: registrarmain registrarmain_pkey; Type: CONSTRAINT; Schema: public; Owner: keylime
--

ALTER TABLE ONLY public.registrarmain
    ADD CONSTRAINT registrarmain_pkey PRIMARY KEY (agent_id);

--
-- PostgreSQL database dump complete
--

