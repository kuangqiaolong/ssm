package com.zking.ssm.base.util;

import io.jsonwebtoken.Claims;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * * JWT验证过滤器，配置顺序 ：CorsFilte-->JwtFilter-->struts2中央控制器
 * 
 * @author Administrator
 *
 */
public class JwtFilter implements Filter {

	// 排除的URL，一般为登陆的URL(请改成自己登陆的URL)
//	private static String EXCLUDE = "^/user/userAction_doLogin\\.action([?].*)?";
	private static String EXCLUDE = "^/user/(userAction_doLogin|captchaAction)\\.action([?].*)?";
//	private static String EXCLUDE = "^/sys/(userAction_doLogin|captchaAction)\\.action([?].*)?";

	private static Pattern PATTERN = Pattern.compile(EXCLUDE);

	private boolean OFF = false;// true关闭jwt令牌验证功能

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
	}

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse resp = (HttpServletResponse) response;
		String path = req.getServletPath();
		if (OFF || isExcludeUrl(path)) {// 登陆直接放行
			chain.doFilter(request, response);
			return;
		}

		// 从客户端请求头中获得令牌并验证
		String jwt = req.getHeader(JwtUtils.JWT_HEADER_KEY);
		Claims claims = this.validateJwtToken(jwt);
		if (null == claims) {
			// resp.setCharacterEncoding("UTF-8");
			resp.sendError(10403, "JWT令牌已过期或已失效");
			return;
		} else {
			String newJwt = JwtUtils.copyJwt(jwt, JwtUtils.JWT_WEB_TTL);
			resp.setHeader(JwtUtils.JWT_HEADER_KEY, newJwt);
			chain.doFilter(request, response);
		}
	}

	/**
	 * 验证jwt令牌，验证通过返回声明(包括公有和私有)，返回null则表示验证失败
	 */
	private Claims validateJwtToken(String jwt) {
		Claims claims = null;
		try {
			if (null != jwt) {
				claims = JwtUtils.parseJwt(jwt);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return claims;
	}

	/**
	 * 是否为排除的URL
	 * 
	 * @param path
	 * @return
	 */
	private boolean isExcludeUrl(String path) {
		Matcher matcher = PATTERN.matcher(path);
		boolean b = matcher.matches();
		if (b) {
			System.out.println("path[" + path + "]直接放行了");
		} else {
			System.out.println("path[" + path + "]需要拦截");
		}
		return b;
	}

	// public static void main(String[] args) {
	// String path = "/sys/userAction_doLogin.action?username=zs&password=123";
	// Matcher matcher = PATTERN.matcher(path);
	// boolean b = matcher.matches();
	// System.out.println(b);
	// }

}
