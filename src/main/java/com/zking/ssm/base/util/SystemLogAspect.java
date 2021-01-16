package com.zking.ssm.base.util;

import org.apache.ibatis.javassist.*;
import org.apache.ibatis.javassist.bytecode.CodeAttribute;
import org.apache.ibatis.javassist.bytecode.LocalVariableAttribute;
import org.apache.ibatis.javassist.bytecode.MethodInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 系统日志对象，用于controller/biz层的日志记录,
 * controller的日志还需要在springmvc-servlet.xml配置如下内容：即对类进行代理，因为controller是基于类而非接口创建的
 * <aop:aspectj-autoproxy proxy-target-class="true" />
 */
@Component
@Aspect
public class SystemLogAspect {

    private static final Logger log = LogManager.getLogger(SystemLogAspect.class);

    /**
     * true关闭Controller层日志，false显示Controller层日志，默认值false
     */
    public static boolean controllerClosed = false;

    /**
     * true关闭Biz层日志，false显示Biz层日志，默认值true
     */
    public static boolean bizClosed = true;


    public SystemLogAspect() {
    }


    @Pointcut("execution(* *..*Controller.do*(..)) || execution(* *..*Controller.add*(..))|| execution(* *..*Controller.edit*(..))|| execution(* *..*Controller.del*(..))|| execution(* *..*Controller.load*(..))|| execution(* *..*Controller.list*(..))")
    public void controller() {
    }

    @Around("controller()")
    public Object controller(ProceedingJoinPoint joinPoint) throws Throwable {
        if (controllerClosed) {
            return joinPoint.proceed();
        } else {
            return invoke(joinPoint);
        }
    }

    @Pointcut("execution(* *..*Biz.*(..))")
    public void biz() {
    }

    @Around("biz()")
    public Object biz(ProceedingJoinPoint joinPoint) throws Throwable {
        if (bizClosed) {
            return joinPoint.proceed();
        } else {
            return invoke(joinPoint);
        }
    }


    private Object invoke(ProceedingJoinPoint joinPoint) throws Throwable {
        String classType = joinPoint.getTarget().getClass().getName();
        Class<?> clazz = Class.forName(classType);
        String clazzName = clazz.getName();
        String methodName = joinPoint.getSignature().getName(); //获取方法名称
        Object[] args = joinPoint.getArgs();//参数

        //获取参数名称和值
        Map<String, Object> nameAndArgs = getFieldsName(this.getClass(), clazzName, methodName, args);
        if (0 == nameAndArgs.size()) {
            log.debug(clazzName + "." + methodName + "方法开始执行，没有参数！");
        } else {
            log.debug(clazzName + "." + methodName + "方法开始执行，参数如下：");
        }

        for (Map.Entry<String, Object> entry : nameAndArgs.entrySet()) {
            log.debug(entry.getKey() + ":" + entry.getValue());
        }

        Object returnValue = joinPoint.proceed(args);
        log.debug(clazzName + "." + methodName + "方法执行结束，返回值如下：");
        log.debug(returnValue);
        return returnValue;
    }

    private Map<String, Object> getFieldsName(Class cls, String clazzName, String methodName, Object[] args) throws NotFoundException {
        Map<String, Object> map = new HashMap<String, Object>();

        ClassPool pool = ClassPool.getDefault();
        ClassClassPath classPath = new ClassClassPath(cls);
        pool.insertClassPath(classPath);

        CtClass cc = pool.get(clazzName);
        CtMethod cm = cc.getDeclaredMethod(methodName);
        MethodInfo methodInfo = cm.getMethodInfo();
        CodeAttribute codeAttribute = methodInfo.getCodeAttribute();
        LocalVariableAttribute attr = (LocalVariableAttribute) codeAttribute.getAttribute(LocalVariableAttribute.tag);
        int pos = Modifier.isStatic(cm.getModifiers()) ? 0 : 1;
        for (int i = 0; i < cm.getParameterTypes().length; i++) {
            map.put(attr.variableName(i + pos), args[i]);//paramNames即参数名
        }
        return map;
    }
}





